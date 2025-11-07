// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

// Calulation of call-to-call priorities.
// For a given pair of calls X and Y, the priority is our guess as to whether
// additional of call Y into a program containing call X is likely to give
// new coverage or not.
// The current algorithm has two components: static and dynamic.
// The static component is based on analysis of argument types. For example,
// if call X and call Y both accept fd[sock], then they are more likely to give
// new coverage together.
// The dynamic component is based on frequency of occurrence of a particular
// pair of syscalls in a single program in corpus. For example, if socket and
// connect frequently occur in programs together, we give higher priority to
// this pair of syscalls.
// Note: the current implementation is very basic, there is no theory behind any
// constants.

func (target *Target) CalculatePriorities(corpus []*Prog) [][]int32 {
	static := target.calcStaticPriorities()
	if len(corpus) != 0 {
		// Let's just sum the static and dynamic distributions.
		dynamic := target.calcDynamicPrio(corpus)
		for i, prios := range dynamic {
			dst := static[i]
			for j, p := range prios {
				dst[j] += p
			}
		}
	}
	return static
}

func (target *Target) calcStaticPriorities() [][]int32 {
	uses := target.calcResourceUsage()
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, weights := range uses {
		for _, w0 := range weights {
			for _, w1 := range weights {
				if w0.call == w1.call {
					// Self-priority is assigned below.
					continue
				}
				// The static priority is assigned based on the direction of arguments. A higher priority will be
				// assigned when c0 is a call that produces a resource and c1 a call that uses that resource.
				prios[w0.call][w1.call] += w0.inout*w1.in*3/2 + w0.inout*w1.inout
			}
		}
	}
	// The value assigned for self-priority (call wrt itself) have to be high, but not too high.
	for c0, pp := range prios {
		var max int32
		for _, p := range pp {
			if p > max {
				max = p
			}
		}
		if max == 0 {
			pp[c0] = 1
		} else {
			pp[c0] = max * 3 / 4
		}
	}
	normalizePrios(prios)
	return prios
}

func (target *Target) calcResourceUsage() map[string]map[int]weights {
	uses := make(map[string]map[int]weights)
	ForeachType(target.Syscalls, func(t Type, ctx *TypeCtx) {
		c := ctx.Meta
		switch a := t.(type) {
		case *ResourceType:
			if target.AuxResources[a.Desc.Name] {
				noteUsage(uses, c, 1, ctx.Dir, "res%v", a.Desc.Name)
			} else {
				str := "res"
				for i, k := range a.Desc.Kind {
					str += "-" + k
					w := int32(10)
					if i < len(a.Desc.Kind)-1 {
						w = 2
					}
					noteUsage(uses, c, w, ctx.Dir, str)
				}
			}
		case *PtrType:
			if _, ok := a.Elem.(*StructType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if _, ok := a.Elem.(*UnionType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if arr, ok := a.Elem.(*ArrayType); ok {
				noteUsage(uses, c, 10, ctx.Dir, "ptrto-%v", arr.Elem.Name())
			}
		case *BufferType:
			switch a.Kind {
			case BufferBlobRand, BufferBlobRange, BufferText, BufferCompressed:
			case BufferString, BufferGlob:
				if a.SubKind != "" {
					noteUsage(uses, c, 2, ctx.Dir, fmt.Sprintf("str-%v", a.SubKind))
				}
			case BufferFilename:
				noteUsage(uses, c, 10, DirIn, "filename")
			default:
				panic("unknown buffer kind")
			}
		case *VmaType:
			noteUsage(uses, c, 5, ctx.Dir, "vma")
		case *IntType:
			switch a.Kind {
			case IntPlain, IntRange:
			default:
				panic("unknown int kind")
			}
		}
	})
	return uses
}

type weights struct {
	call  int
	in    int32
	inout int32
}

func noteUsage(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string, args ...interface{}) {
	id := fmt.Sprintf(str, args...)
	if uses[id] == nil {
		uses[id] = make(map[int]weights)
	}
	callWeight := uses[id][c.ID]
	callWeight.call = c.ID
	if dir != DirOut {
		if weight > uses[id][c.ID].in {
			callWeight.in = weight
		}
	}
	if weight > uses[id][c.ID].inout {
		callWeight.inout = weight
	}
	uses[id][c.ID] = callWeight
}

func (target *Target) calcDynamicPrio(corpus []*Prog) [][]int32 {
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, p := range corpus {
		for idx0, c0 := range p.Calls {
			for _, c1 := range p.Calls[idx0+1:] {
				prios[c0.Meta.ID][c1.Meta.ID]++
			}
		}
	}
	for i := range prios {
		for j, val := range prios[i] {
			// It's more important that some calls do coexist than whether
			// it happened 50 or 100 times.
			// Let's use sqrt() to lessen the effect of large counts.
			prios[i][j] = int32(2.0 * math.Sqrt(float64(val)))
		}
	}
	normalizePrios(prios)
	return prios
}

// normalizePrio distributes |N| * 10 points proportional to the values in the matrix.
func normalizePrios(prios [][]int32) {
	total := 10 * int32(len(prios))
	for _, prio := range prios {
		sum := int32(0)
		for _, p := range prio {
			sum += p
		}
		if sum == 0 {
			continue
		}
		for i, p := range prio {
			prio[i] = p * total / sum
		}
	}

}

// ChooseTable allows to do a weighted choice of a syscall for a given syscall
// based on call-to-call priorities and a set of enabled and generatable syscalls.
type ChoiceTable struct {
	target *Target
	runs   [][]int32
	calls  []*Syscall

	// adding config call
	df_configCalls []*Syscall
	// set-reset call mappping
	df_configCallsMap map[int]int
	// config-syscall priorities
	df_configPrios [][]int32
	// syscall.ID to array index mapping
	df_syscall_idValToArrayIdx map[int]int
	df_config_idValToArrayIdx  map[int]int
	df_config_ArrayIdxToIdVal  map[int]int
	df_configCallsMap_reverse  map[int]int
	df_proconfigIdStart        int
	df_proconfigIdEnd          int
	df_sysconfigIdStart        int
	df_sysconfigIdEnd          int
}

func (target *Target) BuildChoiceTable(corpus []*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	// df: load static relation table here

	target.DF_loadConfigTable(target.DF_staticPriosPath)

	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
			// log.Logf(1, "df: %v", c.Name, c.ID, c.NR)
		}
	}

	df_syscall_idValToArrayIdx := make(map[int]int)
	df_config_idValToArrayIdx := make(map[int]int)
	df_config_ArrayIdxToIdVal := make(map[int]int)
	syscall_idx := 0
	config_idx := 0
	df_proconfigIdStart := 0
	df_proconfigIdEnd := 0
	df_sysconfigIdStart := 0
	df_sysconfigIdEnd := 0
	for _, c := range target.Syscalls {
		// log.Logf(1, "df: %v", c.Name, c.ID, c.NR)
		if strings.HasPrefix(c.Name, "syz_proconfig") || strings.HasPrefix(c.Name, "syz_sysconfig") {
			df_config_idValToArrayIdx[config_idx] = c.ID
			df_config_ArrayIdxToIdVal[c.ID] = config_idx
			config_idx++
			if df_proconfigIdStart == 0 && strings.HasPrefix(c.Name, "syz_proconfig") {
				df_proconfigIdStart = c.ID
			}
			if df_sysconfigIdStart == 0 && strings.HasPrefix(c.Name, "syz_sysconfig") {
				df_sysconfigIdStart = c.ID
			}
			if strings.HasPrefix(c.Name, "syz_proconfig") {
				df_proconfigIdEnd = c.ID
			}
			if strings.HasPrefix(c.Name, "syz_sysconfig") {
				df_sysconfigIdEnd = c.ID
			}
		} else {
			df_syscall_idValToArrayIdx[c.ID] = syscall_idx
			syscall_idx++
		}

	}
	log.Logf(1, "df: syscall_idx: %v, config_idx: %v", syscall_idx, config_idx)
	// log.Logf(1, "df: syscall_idValToArrayIdx: %v, config_idValToArrayIdx: %v", df_syscall_idValToArrayIdx, df_config_idValToArrayIdx)
	noGenerateCalls := make(map[int]bool)
	enabledCalls := make(map[*Syscall]bool)
	for call := range enabled {
		if call.Attrs.NoGenerate {
			noGenerateCalls[call.ID] = true
		} else if !call.Attrs.Disabled {
			enabledCalls[call] = true
		}
	}
	var generatableCalls []*Syscall
	for c := range enabledCalls {
		generatableCalls = append(generatableCalls, c)
	}
	if len(generatableCalls) == 0 {
		panic("no syscalls enabled and generatable")
	}
	sort.Slice(generatableCalls, func(i, j int) bool {
		return generatableCalls[i].ID < generatableCalls[j].ID
	})
	for _, p := range corpus {
		for _, call := range p.Calls {
			if !enabledCalls[call.Meta] && !noGenerateCalls[call.Meta.ID] {
				fmt.Printf("corpus contains disabled syscall %v %v\n", call.Meta.Name, call.Meta.ID)
				panic("disabled syscall")
			}
		}
	}
	prios := target.CalculatePriorities(corpus)
	run := make([][]int32, len(target.Syscalls))
	// ChoiceTable.runs[][] contains cumulated sum of weighted priority numbers.
	// This helps in quick binary search with biases when generating programs.
	// This only applies for system calls that are enabled for the target.
	for i := range run {
		if !enabledCalls[target.Syscalls[i]] {
			continue
		}
		run[i] = make([]int32, len(target.Syscalls))
		var sum int32
		for j := range run[i] {
			if enabledCalls[target.Syscalls[j]] {
				sum += prios[i][j]
			}
			run[i][j] = sum
		}
	}

	df_configCalls, df_configCallsMap, df_configPrios, df_configCallsMap_reverse := target.DF_build_configTable(enabledCalls)
	for i, row := range df_configPrios {
		// We'll create a running total
		runningSum := int32(0)
		for j, val := range row {
			runningSum = runningSum + val
			// Update the original array element with the running sum
			df_configPrios[i][j] = runningSum
		}
	}

	return &ChoiceTable{target, run, generatableCalls, df_configCalls, df_configCallsMap, df_configPrios, df_syscall_idValToArrayIdx, df_config_idValToArrayIdx, df_config_ArrayIdxToIdVal, df_configCallsMap_reverse, df_proconfigIdStart, df_proconfigIdEnd, df_sysconfigIdStart, df_sysconfigIdEnd}
}

func (ct *ChoiceTable) DF_UpdateChoiceTable(Prog *Prog) {

	config_ids := []int{}
	syscall_ids := []int{}
	for _, call := range Prog.Calls {
		if strings.HasPrefix(call.Meta.Name, "syz_proconfig") || strings.HasPrefix(call.Meta.Name, "syz_sysconfig") {
			log.Logf(1, "df: Hit on relation", call.Meta.Name)
			config_ids = append(config_ids, call.Meta.ID)
		} else {
			syscall_ids = append(syscall_ids, call.Meta.ID)
		}
	}
	// log.Logf(1, "df: syscall_ids: %v, config_ids: %v, %v, %v", syscall_ids, config_ids, len(syscall_ids), len(config_ids))
	if len(config_ids) > 0 {
		log.Logf(1, "df: Updating config table")
		for i := range syscall_ids {
			syscall_idx := ct.df_syscall_idValToArrayIdx[syscall_ids[i]]
			for j := range config_ids {
				config_idx := ct.df_config_idValToArrayIdx[config_ids[j]]
				ct.df_configPrios[syscall_idx][config_idx] = int32(2.0 * math.Sqrt(float64(ct.df_configPrios[syscall_idx][config_idx])))
			}
		}
		normalizePrios(ct.df_configPrios)
		// For each sub-slice in df_configPrios
		for i, row := range ct.df_configPrios {
			// We'll create a running total
			runningSum := int32(0)
			for j, val := range row {
				runningSum = runningSum + val
				// Update the original array element with the running sum
				ct.df_configPrios[i][j] = runningSum
			}
		}

	}
}

func (ct *ChoiceTable) DF_LowerChoiceTable() {
	// For each sub-slice in df_configPrios
	for i, row := range ct.df_configPrios {
		// We'll create a running total
		for j := range row {
			if ct.df_configPrios[i][j] >= 1 {
				ct.df_configPrios[i][j]--
			}
		}
	}
}

// DF_loadConfigTable reads a CSV file and populates df_staticPrios.
func (target *Target) DF_loadConfigTable(filePath string) {
	log.Logf(1, "df: Loading config table from %s", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		log.Logf(1, "Error opening file:", err)
		target.df_staticPrios = nil
		return
	}
	defer file.Close()

	reader := csv.NewReader(bufio.NewReader(file))
	log.Logf(1, "df: Loading config table from %d", reader)
	// Read all rows from the CSV.
	records, err := reader.ReadAll()
	if err != nil {
		log.Logf(1, "df: Error reading CSV file:", err)
		target.df_staticPrios = nil
		return
	}

	var allData [][]int32
	// Convert each row (slice of strings) into a slice of int32.
	for _, rec := range records {
		var row []int32
		for _, val := range rec {
			num, convErr := strconv.Atoi(val)
			if convErr != nil {
				// Handle conversion error (skip/break as needed).
				log.Logf(1, "df: Error converting string to int:", convErr)
				// You could choose to continue or return here.
				continue
			}
			row = append(row, int32(num))
		}
		allData = append(allData, row)
	}

	target.df_staticPrios = allData
	log.Logf(1, "df: Successfully loaded %d rows and %d cols from CSV.\n", len(allData), len(allData[0]))
}

func (target Target) DF_build_configTable(enabledCalls map[*Syscall]bool) ([]*Syscall, map[int]int, [][]int32, map[int]int) {
	// df: mk config call array and map
	log.Logf(1, "df: mk config call array and map")
	resetCalls := make(map[string]int)
	setCalls := make(map[string]int)

	df_configCallsMap := make(map[int]int)
	df_configCallsMap_reverse := make(map[int]int)
	df_configCalls := make([]*Syscall, 0)

	for _, syscall := range target.Syscalls {
		if strings.HasPrefix(syscall.Name, "syz_proconfig") || strings.HasPrefix(syscall.Name, "syz_sysconfig") {
			df_configCalls = append(df_configCalls, syscall)
		}
		if strings.HasPrefix(syscall.Name, "syz_proconfig_reset__") {
			key := strings.TrimPrefix(syscall.Name, "syz_proconfig_reset__")
			resetCalls[key] = syscall.ID
			// log.Logf(1, "df: reset: %v-%v", key, syscall.ID)
		} else if strings.HasPrefix(syscall.Name, "syz_proconfig_set__") {
			key := strings.TrimPrefix(syscall.Name, "syz_proconfig_set__")
			setCalls[key] = syscall.ID
			// log.Logf(1, "df: set: %v-%v", key, syscall.ID)
		}
		if strings.HasPrefix(syscall.Name, "syz_sysconfig_reset__") {
			key := strings.TrimPrefix(syscall.Name, "syz_sysconfig_reset__")
			resetCalls[key] = syscall.ID
			// log.Logf(1, "df: reset: %v-%v", key, syscall.ID)
		} else if strings.HasPrefix(syscall.Name, "syz_sysconfig_set__") {
			key := strings.TrimPrefix(syscall.Name, "syz_sysconfig_set__")
			setCalls[key] = syscall.ID
			// log.Logf(1, "df: set: %v-%v", key, syscall.ID)
		}

	}

	for key, setID := range setCalls {
		if resetID, exists := resetCalls[key]; exists {
			df_configCallsMap[setID] = resetID
			df_configCallsMap_reverse[resetID] = setID
		}
	}

	df_configPrios := target.df_staticPrios
	return df_configCalls, df_configCallsMap, df_configPrios, df_configCallsMap_reverse
}

func (ct *ChoiceTable) Enabled(call int) bool {
	return ct.Generatable(call)
}

func (ct *ChoiceTable) Generatable(call int) bool {
	return ct.runs[call] != nil
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	if r.Intn(100) < 5 {
		// Let's make 5% decisions totally at random.
		return ct.calls[r.Intn(len(ct.calls))].ID
	}
	if bias < 0 {
		bias = ct.calls[r.Intn(len(ct.calls))].ID
	}
	if !ct.Generatable(bias) {
		log.Logf(1, "bias to disabled or non-generatable syscall %v\n", ct.target.Syscalls[bias].ID)
		fmt.Printf("bias to disabled or non-generatable syscall %v\n", ct.target.Syscalls[bias].Name)
		panic("disabled or non-generatable syscall")
	}
	run := ct.runs[bias]
	// df: chose a value from len(run)-len(configcall)
	// df_runSum := int(run[len(run)-1]) - int(len(ct.df_configCalls)-1)
	runSum := int(run[len(run)-1])

	x := int32(r.Intn(runSum) + 1)
	res := sort.Search(len(run), func(i int) bool {
		return run[i] >= x
	})
	if !ct.Generatable(res) {
		panic("selected disabled or non-generatable syscall")
	}
	return res
}

func (ct *ChoiceTable) DF_choiceConfigcall(r *rand.Rand, syscall_idx int) int {
	syscall_array_idx := ct.df_syscall_idValToArrayIdx[syscall_idx]
	log.Logf(1, "df: syscall_idx: %v, array_idx: %v", syscall_idx, syscall_array_idx)
	syscall := ct.df_configPrios[syscall_array_idx]
	log.Logf(1, "df: len(syscall)-1: %v, %v", len(syscall)-1, syscall)
	df_runSum := int(syscall[len(syscall)-1])
	log.Logf(1, "df: df_runSum: %v", df_runSum)
	if df_runSum > 0 {
		x := int32(r.Intn(df_runSum) + 1)
		log.Logf(1, "df: df_runSum: %v, x: %v", df_runSum, x)
		res := sort.Search(len(syscall), func(i int) bool {
			return syscall[i] >= x
		})
		config_array_idx := ct.df_config_idValToArrayIdx[res]
		return config_array_idx
	} else {
		log.Logf(1, "df: df_runSum is 0")
		// return range from ct.df_configIDstar to ct.df_configIdEnd
		return ct.df_proconfigIdStart + r.Intn(ct.df_proconfigIdEnd-ct.df_proconfigIdStart)
	}

}

func (ct *ChoiceTable) DF_choiceRestConfigcall(r *rand.Rand, config_id int) int {
	// iterate from ct.df_configCallsMap[config_idx-10, config_idx+10]

	// config_Idx := ct.df_config_idValToArrayIdx[config_id]
	reset_config_id := ct.df_configCallsMap[config_id]

	if reset_config_id == 0 {
		reset_config_id = ct.df_configCallsMap_reverse[config_id]
	}
	log.Logf(1, "df: config_idx: %v,  reset_config_id: %v, reset_config_array_idx: %v", config_id, reset_config_id, reset_config_id)
	return reset_config_id
}
