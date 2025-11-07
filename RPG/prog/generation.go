// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	log.Logf(1, "Generating program with %v calls", ncalls)
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	log.Logf(1, "df: Generating program with %v calls, p.Calls = %v", ncalls, len(p.Calls))
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			// TODO: check if the call is configcall
			if strings.HasPrefix(c.Meta.Name, "syz_proconfig") || strings.HasPrefix(c.Meta.Name, "syz_sysconfig") {
				p.Calls = append(p.Calls, c)
			} else if r.randInt(2) == 0 { // Assuming randInt generates an integer 0 or 1

				configCall := r.df_generateConfigSet(s, p, c.Meta.ID)
				log.Logf(1, "df: configCall = %v", configCall[0].Meta.Name, configCall[0].Meta.ID)
				configResetCall := r.df_generateConfigReset(s, p, configCall[0].Meta.ID)
				log.Logf(1, "df: configResetCall = %v", configResetCall[0].Meta.Name, configResetCall[0].Meta.ID)
				if strings.Contains(configCall[0].Meta.Name, "reset") {
					// switch configCall and configResetCall
					tmp := configCall
					configCall = configResetCall
					configResetCall = tmp
				}
				p.Calls = append(p.Calls, configCall[0])
				p.Calls = append(p.Calls, c)
				p.Calls = append(p.Calls, configResetCall[0])
			} else {
				// Only append the main call
				p.Calls = append(p.Calls, c)
			}
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}
