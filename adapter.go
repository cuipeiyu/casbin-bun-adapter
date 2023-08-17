// Copyright (c) 2022 cuipeiyu (i@cuipeiyu.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package casbinbunadapter

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/mssqldialect"
	"github.com/uptrace/bun/dialect/mysqldialect"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/pkg/errors"
)

const (
	DefaultSchemaName = "public"
	DefaultTableName  = "casbin_rule"
)

var (
	ErrUnknownDriver = errors.New("unknown driver")
)

type Adapter struct {
	client *bun.DB
	ctx    context.Context

	filtered bool

	schemaName string
	tableName  string
}

type CasbinRule struct {
	Id    int64  `bun:"id,pk,autoincrement"`
	Ptype string `bun:",nullzero,notnull"`
	V0    string `bun:",nullzero,notnull"`
	V1    string `bun:",nullzero,notnull"`
	V2    string `bun:",nullzero,notnull"`
	V3    string `bun:",nullzero,notnull"`
	V4    string `bun:",nullzero,notnull"`
	V5    string `bun:",nullzero,notnull"`
	V6    string `bun:",nullzero,notnull"`
	V7    string `bun:",nullzero,notnull"`
}

type Filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

type Option func(a *Adapter) error

func WithTableName(schema, table string) Option {
	return func(a *Adapter) error {
		a.schemaName = schema
		a.tableName = table
		return nil
	}
}

func open(driverName, dataSourceName string) (*bun.DB, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	var b *bun.DB
	switch strings.ToLower(driverName) {
	case "pg", "postgre", "postgres", "postgresql":
		b = bun.NewDB(db, pgdialect.New())
	case "mysql":
		b = bun.NewDB(db, mysqldialect.New())
	case "mssql":
		b = bun.NewDB(db, mssqldialect.New())
	default:
		return nil, ErrUnknownDriver
	}
	return b, nil
}

// NewAdapter returns an adapter by driver name and data source string.
func NewAdapter(driverName, dataSourceName string, options ...Option) (*Adapter, error) {
	client, err := open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		client:     client,
		ctx:        context.Background(),
		schemaName: DefaultSchemaName,
		tableName:  DefaultTableName,
	}
	for _, option := range options {
		if err := option(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// NewAdapterWithClient create an adapter with client passed in.
// This method does not ensure the existence of database, user should create database manually.
func NewAdapterWithClient(client *bun.DB, options ...Option) (*Adapter, error) {
	a := &Adapter{
		client:     client,
		ctx:        context.Background(),
		schemaName: DefaultSchemaName,
		tableName:  DefaultTableName,
	}
	for _, option := range options {
		if err := option(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *Adapter) getFullTableName() string {
	if a.schemaName == "" {
		return a.tableName
	}
	return a.schemaName + "." + a.tableName
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var policies []*CasbinRule
	err := a.client.NewSelect().Table(a.getFullTableName()).Order("id ASC").Scan(a.ctx, &policies)
	if err != nil {
		return err
	}
	for _, policy := range policies {
		loadPolicyLine(policy, model)
	}
	return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
// Filter parameter here is a Filter structure
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {

	filterValue, ok := filter.(Filter)
	if !ok {
		return fmt.Errorf("invalid filter type: %v", reflect.TypeOf(filter))
	}

	session := a.client.NewSelect().Table(a.getFullTableName())

	if len(filterValue.Ptype) != 0 {
		session.Where("ptype in (?)", bun.In(filterValue.Ptype))
	}
	if len(filterValue.V0) != 0 {
		session.Where("v0 in (?)", bun.In(filterValue.V0))
	}
	if len(filterValue.V1) != 0 {
		session.Where("v1 in (?)", bun.In(filterValue.V1))
	}
	if len(filterValue.V2) != 0 {
		session.Where("v2 in (?)", bun.In(filterValue.V2))
	}
	if len(filterValue.V3) != 0 {
		session.Where("v3 in (?)", bun.In(filterValue.V3))
	}
	if len(filterValue.V4) != 0 {
		session.Where("v4 in (?)", bun.In(filterValue.V4))
	}
	if len(filterValue.V5) != 0 {
		session.Where("v5 in (?)", bun.In(filterValue.V5))
	}

	var lines []*CasbinRule
	err := session.Scan(a.ctx, &lines)
	if err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}
	a.filtered = true

	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.filtered
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	return a.WithTx(func(tx bun.Tx) error {
		_, err := tx.NewTruncateTable().
			Table(a.getFullTableName()).
			Exec(a.ctx)
		if err != nil {
			return err
		}

		lines := make([]*CasbinRule, 0)

		for ptype, ast := range model["p"] {
			for _, policy := range ast.Policy {
				line := a.savePolicyLine(tx, ptype, policy)
				lines = append(lines, line)
			}
		}

		for ptype, ast := range model["g"] {
			for _, policy := range ast.Policy {
				line := a.savePolicyLine(tx, ptype, policy)
				lines = append(lines, line)
			}
		}

		_, err = tx.NewInsert().Model(&lines).ModelTableExpr(a.getFullTableName()).Exec(a.ctx)
		return err
	})
}

// AddPolicy adds a policy rule to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.WithTx(func(tx bun.Tx) error {
		line := a.savePolicyLine(tx, ptype, rule)
		_, err := tx.NewInsert().Model(line).ModelTableExpr(a.getFullTableName()).Exec(a.ctx)
		return err
	})
}

// RemovePolicy removes a policy rule from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.WithTx(func(tx bun.Tx) error {
		instance := a.toInstance(ptype, rule)

		_, err := tx.NewDelete().
			Table(a.getFullTableName()).
			Where("ptype = ?", instance.Ptype).
			Where("v0 = ?", instance.V0).
			Where("v1 = ?", instance.V1).
			Where("v2 = ?", instance.V2).
			Where("v3 = ?", instance.V3).
			Where("v4 = ?", instance.V4).
			Where("v5 = ?", instance.V5).
			Exec(a.ctx)
		return err
	})
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.WithTx(func(tx bun.Tx) error {
		build := tx.NewDelete().Table(a.getFullTableName())

		build.Where("ptype = ?", ptype)

		if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
			build.Where("v0 = ?", fieldValues[0-fieldIndex])
		}
		if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
			build.Where("v1 = ?", fieldValues[1-fieldIndex])
		}
		if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
			build.Where("v2 = ?", fieldValues[2-fieldIndex])
		}
		if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
			build.Where("v3 = ?", fieldValues[3-fieldIndex])
		}
		if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
			build.Where("v4 = ?", fieldValues[4-fieldIndex])
		}
		if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
			build.Where("v5 = ?", fieldValues[5-fieldIndex])
		}
		_, err := build.Exec(a.ctx)
		return err
	})
}

// AddPolicies adds policy rules to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return a.WithTx(func(tx bun.Tx) error {
		return a.createPolicies(tx, ptype, rules)
	})
}

// RemovePolicies removes policy rules from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.WithTx(func(tx bun.Tx) error {
		for _, rule := range rules {
			instance := a.toInstance(ptype, rule)
			if _, err := tx.NewDelete().Table(a.getFullTableName()).
				Where("ptype = ?", instance.Ptype).
				Where("v0 = ?", instance.V0).
				Where("v1 = ?", instance.V1).
				Where("v2 = ?", instance.V2).
				Where("v3 = ?", instance.V3).
				Where("v4 = ?", instance.V4).
				Where("v5 = ?", instance.V5).
				Exec(a.ctx); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *Adapter) WithTx(fn func(tx bun.Tx) error) error {
	tx, err := a.client.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if v := recover(); v != nil {
			_ = tx.Rollback()
			panic(v)
		}
	}()
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			err = errors.Wrapf(err, "rolling back transaction: %v", rerr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrapf(err, "committing transaction: %v", err)
	}
	return nil
}

func loadPolicyLine(line *CasbinRule, model model.Model) {
	var p = []string{line.Ptype,
		line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}

	var lineText string
	if line.V5 != "" {
		lineText = strings.Join(p, ", ")
	} else if line.V4 != "" {
		lineText = strings.Join(p[:6], ", ")
	} else if line.V3 != "" {
		lineText = strings.Join(p[:5], ", ")
	} else if line.V2 != "" {
		lineText = strings.Join(p[:4], ", ")
	} else if line.V1 != "" {
		lineText = strings.Join(p[:3], ", ")
	} else if line.V0 != "" {
		lineText = strings.Join(p[:2], ", ")
	}

	persist.LoadPolicyLine(lineText, model)
}

func (a *Adapter) toInstance(ptype string, rule []string) *CasbinRule {
	instance := &CasbinRule{}

	instance.Ptype = ptype

	if len(rule) > 0 {
		instance.V0 = rule[0]
	}
	if len(rule) > 1 {
		instance.V1 = rule[1]
	}
	if len(rule) > 2 {
		instance.V2 = rule[2]
	}
	if len(rule) > 3 {
		instance.V3 = rule[3]
	}
	if len(rule) > 4 {
		instance.V4 = rule[4]
	}
	if len(rule) > 5 {
		instance.V5 = rule[5]
	}
	return instance
}

func (a *Adapter) savePolicyLine(tx bun.Tx, ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{
		Ptype: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// UpdatePolicy updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.WithTx(func(tx bun.Tx) error {
		rule := a.toInstance(ptype, oldRule)
		line := tx.NewUpdate().
			Model(rule).
			ModelTableExpr(a.getFullTableName()).
			Where("ptype = ?", rule.Ptype).
			Where("v0 = ?", rule.V0).
			Where("v1 = ?", rule.V1).
			Where("v2 = ?", rule.V2).
			Where("v3 = ?", rule.V3).
			Where("v4 = ?", rule.V4).
			Where("v5 = ?", rule.V5)

		rule = a.toInstance(ptype, newPolicy)
		line.
			Set("v0 = ?", rule.V0).
			Set("v1 = ?", rule.V1).
			Set("v2 = ?", rule.V2).
			Set("v3 = ?", rule.V3).
			Set("v4 = ?", rule.V4).
			Set("v5 = ?", rule.V5)

		_, err := line.Exec(a.ctx)
		return err
	})
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	return a.WithTx(func(tx bun.Tx) error {
		for _, policy := range oldRules {
			rule := a.toInstance(ptype, policy)

			if _, err := tx.NewDelete().
				Table(a.getFullTableName()).
				Where("ptype = ?", rule.Ptype).
				Where("v0 = ?", rule.V0).
				Where("v1 = ?", rule.V1).
				Where("v2 = ?", rule.V2).
				Where("v3 = ?", rule.V3).
				Where("v4 = ?", rule.V4).
				Where("v5 = ?", rule.V5).
				Exec(a.ctx); err != nil {
				return err
			}
		}
		lines := make([]*CasbinRule, 0)
		for _, policy := range newRules {
			lines = append(lines, a.savePolicyLine(tx, ptype, policy))
		}
		_, err := tx.NewInsert().Model(&lines).ModelTableExpr(a.getFullTableName()).Exec(a.ctx)
		return err
	})
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	oldPolicies := make([][]string, 0)
	err := a.WithTx(func(tx bun.Tx) error {
		line := tx.NewSelect().Table(a.getFullTableName())
		if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
			line = line.Where("v0 = ?", fieldValues[0-fieldIndex])
		}
		if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
			line = line.Where("v1 = ?", fieldValues[1-fieldIndex])
		}
		if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
			line = line.Where("v2 = ?", fieldValues[2-fieldIndex])
		}
		if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
			line = line.Where("v3 = ?", fieldValues[3-fieldIndex])
		}
		if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
			line = line.Where("v4 = ?", fieldValues[4-fieldIndex])
		}
		if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
			line = line.Where("v5 = ?", fieldValues[5-fieldIndex])
		}
		rules := make([]*CasbinRule, 0)
		err := line.Scan(a.ctx, &rules)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if _, err := tx.NewDelete().
				Table(a.getFullTableName()).
				Where("id = ?", rule.Id).
				Exec(a.ctx); err != nil {
				return err
			}
		}
		a.createPolicies(tx, ptype, newPolicies)
		for _, rule := range rules {
			oldPolicies = append(oldPolicies, CasbinRuleToStringArray(rule))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return oldPolicies, nil
}

func (a *Adapter) createPolicies(tx bun.Tx, ptype string, policies [][]string) error {
	lines := make([]*CasbinRule, 0)
	for _, policy := range policies {
		lines = append(lines, a.savePolicyLine(tx, ptype, policy))
	}
	_, err := tx.NewInsert().Model(&lines).ModelTableExpr(a.getFullTableName()).Exec(a.ctx)
	return err
}

func CasbinRuleToStringArray(rule *CasbinRule) []string {
	arr := make([]string, 0)
	if rule.V0 != "" {
		arr = append(arr, rule.V0)
	}
	if rule.V1 != "" {
		arr = append(arr, rule.V1)
	}
	if rule.V2 != "" {
		arr = append(arr, rule.V2)
	}
	if rule.V3 != "" {
		arr = append(arr, rule.V3)
	}
	if rule.V4 != "" {
		arr = append(arr, rule.V4)
	}
	if rule.V5 != "" {
		arr = append(arr, rule.V5)
	}
	return arr
}
