// Copyright 2018 Palantir Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"context"
	"slices"

	"github.com/palantir/go-githubapp/appconfig"
	"github.com/palantir/policy-bot/policy/approval"
	"github.com/palantir/policy-bot/policy/common"
	"github.com/palantir/policy-bot/policy/disapproval"
	"github.com/palantir/policy-bot/pull"
	"github.com/pkg/errors"
)

// RemoteConfig allows the use of a remote policy file, rather than a local one. The Remote value
// should follow the format `org/repo`. An example: `palantir/policy-bot`. The Path is optional,
// with the default value being the configured default policy file location. The Ref is optional,
// and the default branch of the Remote repository will be used.
type RemoteConfig struct {
	Remote string `yaml:"remote,omitempty"`
	Path   string `yaml:"path,omitempty"`
	Ref    string `yaml:"ref,omitempty"`
}

type Config struct {
	Policy           Policy             `yaml:"policy,omitempty"`
	ApprovalDefaults *approval.Defaults `yaml:"approval_defaults,omitempty"`
	ApprovalRules    []*approval.Rule   `yaml:"approval_rules,omitempty"`
	Slots            Slots              `yaml:"slots,omitempty"`
}

type Slots map[string]approval.Policy

type Policy struct {
	Approval        approval.Policy      `yaml:"approval,omitempty"`
	ApprovalExtends *appconfig.RemoteRef `yaml:"approval_extends,omitempty"`
	Disapproval     *disapproval.Policy  `yaml:"disapproval,omitempty"`
}

// ValidateApprovalExtends checks the extension before a loader fetches its parent.
func (p Policy) ValidateApprovalExtends() error {
	if p.ApprovalExtends == nil {
		return nil
	}
	if p.Approval != nil {
		return errors.New("approval and approval_extends cannot both be specified")
	}
	if _, _, err := p.ApprovalExtends.SplitRemote(); err != nil {
		return errors.WithMessage(err, "invalid approval_extends")
	}
	return nil
}

// GlobalOptions defines server-level properties that affect policy parsing, like default or override values.
type GlobalOptions struct {
	// IgnoreEditedComments, if non-nil, overrides the value of this option in
	// all rules. If true, editing a comment will invalidate the comment for
	// approval in all policies.
	IgnoreEditedComments *bool

	// ApprovalDefaults defines server-level default values for policies. For
	// instance, this can change the default approval strings for all policies.
	ApprovalDefaults *approval.Defaults
}

func ParsePolicy(c *Config, opts *GlobalOptions) (common.Evaluator, error) {
	parsed, err := ParsePolicyWithParent(c, nil, opts)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

// ParsedPolicy provides the evaluator, event methods, and rule lookup for one
// resolved policy. Slot rule lookup uses the file that supplied the slot content.
type ParsedPolicy struct {
	evaluator
	baseRules map[string]*approval.Rule
	slotRules map[string]map[string]*approval.Rule
	methods   []*common.Methods
}

func (p *ParsedPolicy) Methods() []*common.Methods {
	return p.methods
}

func (p *ParsedPolicy) FindApprovalRule(slot, name string) *approval.Rule {
	if slot == "" {
		return p.baseRules[name]
	}
	return p.slotRules[slot][name]
}

// ParsePolicyWithParent applies the child's slot content to the parent's approval
// policy. Rules use the defaults from the file that defines them, and only the
// child's disapproval policy applies. Pass a nil parent for a standalone policy.
func ParsePolicyWithParent(child, parent *Config, opts *GlobalOptions) (*ParsedPolicy, error) {
	if err := child.Policy.ValidateApprovalExtends(); err != nil {
		return nil, err
	}
	if parent == nil {
		if child.Policy.ApprovalExtends != nil {
			return nil, errors.New("approval_extends requires a resolved parent")
		}
		file, err := parsePolicyFile(child, opts)
		if err != nil {
			return nil, err
		}
		parsed := &ParsedPolicy{slotRules: make(map[string]map[string]*approval.Rule)}
		parsed.applySlotContents(file, file.slots)
		return parsed.complete(file, child.Policy.Disapproval, child.ApprovalRules)
	}
	if child.Policy.ApprovalExtends == nil {
		return nil, errors.New("a parent was supplied without approval_extends")
	}
	if parent.Policy.ApprovalExtends != nil {
		return nil, errors.New("an approval parent cannot specify approval_extends")
	}
	base, err := parsePolicyFile(parent, opts)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to parse parent approval policy")
	}
	extension, err := parsePolicyFile(child, opts)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to parse child approval policy")
	}
	parsed := &ParsedPolicy{slotRules: make(map[string]map[string]*approval.Rule)}
	parsed.applySlotContents(base, base.slots)
	parsed.applySlotContents(extension, base.slots)
	return parsed.complete(base, child.Policy.Disapproval, base.approval.Rules())
}

// parsedFile keeps per-file parsing separate from filling slots and validating
// required content in the completed policy.
type parsedFile struct {
	approval     approval.Evaluator
	rules        map[string]*approval.Rule
	slots        map[string]*approval.SlotRule
	slotContents map[string]approval.Evaluator
}

func parsePolicyFile(c *Config, opts *GlobalOptions) (*parsedFile, error) {
	rules, err := prepareRules(c, opts)
	if err != nil {
		return nil, err
	}
	evalApproval, slots, err := c.Policy.Approval.Parse(rules)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse approval policy")
	}
	contents := make(map[string]approval.Evaluator, len(c.Slots))
	for name, slotContent := range c.Slots {
		if name == "" {
			return nil, errors.New("slot name must be nonempty")
		}
		slotEvaluator, err := slotContent.ParseAsSlotContent(rules)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse slot content %q", name)
		}
		if slots[name] == nil && c.Policy.ApprovalExtends == nil {
			return nil, errors.Errorf("slot content %q does not match a declared slot", name)
		}
		contents[name] = slotEvaluator
	}
	return &parsedFile{approval: evalApproval, rules: rules, slots: slots, slotContents: contents}, nil
}

func (p *ParsedPolicy) complete(base *parsedFile, evalDisapproval *disapproval.Policy, rules []*approval.Rule) (*ParsedPolicy, error) {
	var missing []string
	for name, slot := range base.slots {
		if slot.Required && slot.Child == nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, errors.Errorf("required slots are empty: %q", missing)
	}

	for _, rule := range rules {
		p.methods = append(p.methods, rule.Options.GetMethods())
	}
	if evalDisapproval == nil {
		evalDisapproval = &disapproval.Policy{}
	} else {
		p.methods = append(p.methods,
			evalDisapproval.Options.GetDisapproveMethods(),
			evalDisapproval.Options.GetRevokeMethods())
	}
	p.evaluator = evaluator{approval: base.approval, disapproval: evalDisapproval}
	p.baseRules = base.rules
	return p, nil
}

func prepareRules(c *Config, opts *GlobalOptions) (map[string]*approval.Rule, error) {
	// Build the options hierarchy in reverse order. When reading an option,
	// values are tried in the following order:
	//
	// 1. Rule
	// 2. Policy default
	// 3. Configurable server default
	// 4. Hardcoded server default
	//
	defaultApprovalOptions := &approval.Options{
		Methods: approval.DefaultMethods(),
	}
	if opts != nil && opts.ApprovalDefaults != nil {
		defaultApprovalOptions = setDefaultOptions(defaultApprovalOptions, opts.ApprovalDefaults.Options)
	}
	if c.ApprovalDefaults != nil {
		defaultApprovalOptions = setDefaultOptions(defaultApprovalOptions, c.ApprovalDefaults.Options)
	}

	rulesByName := make(map[string]*approval.Rule)
	for _, r := range c.ApprovalRules {
		if _, exists := rulesByName[r.Name]; exists {
			return nil, errors.Errorf("duplicate approval rule name %q", r.Name)
		}

		// Set policy and server rule defaults
		r.Options.Defaults = defaultApprovalOptions

		// Override rule options controlled by the server
		if opts != nil {
			if opts.IgnoreEditedComments != nil {
				r.Options.IgnoreEditedComments = opts.IgnoreEditedComments
			}
		}

		rulesByName[r.Name] = r
	}

	return rulesByName, nil
}

func (p *ParsedPolicy) applySlotContents(file *parsedFile, slots map[string]*approval.SlotRule) {
	for name, slotEvaluator := range file.slotContents {
		slot := slots[name]
		if slot == nil {
			continue
		}
		slot.Child = slotEvaluator
		if slotEvaluator == nil {
			delete(p.slotRules, name)
		} else {
			p.slotRules[name] = file.rules
		}
	}
}

func setDefaultOptions(existing *approval.Options, next *approval.Options) *approval.Options {
	if next != nil {
		next.Defaults = existing
		return next
	}
	return existing
}

type evaluator struct {
	approval    common.Evaluator
	disapproval common.Evaluator
}

func (e evaluator) Trigger() common.Trigger {
	return e.approval.Trigger() | e.disapproval.Trigger()
}

func (e evaluator) Evaluate(ctx context.Context, prctx pull.Context) (res common.Result) {
	disapproval := e.disapproval.Evaluate(ctx, prctx)
	approval := e.approval.Evaluate(ctx, prctx)

	res.Name = "policy"
	res.Children = []*common.Result{&approval, &disapproval}

	for _, r := range res.Children {
		if r.Error != nil {
			res.Error = r.Error
		}
	}

	switch {
	case res.Error != nil:
	case disapproval.Status == common.StatusDisapproved:
		res.Status = common.StatusDisapproved
		res.StatusDescription = disapproval.StatusDescription
	default:
		res.Status = approval.Status
		res.StatusDescription = approval.StatusDescription
	}
	return
}
