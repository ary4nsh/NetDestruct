// Package cli is a minimal stdlib CLI for NetDestruct.
// Supports GNU long flags, optional short flags, NoOptDefVal, and interspersed args.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ErrHelp is returned when -h/--help is requested.
var ErrHelp = errors.New("help requested")

// Value is the flag storage interface.
type Value interface {
	String() string
	Set(string) error
	Type() string
}

type boolFlag interface {
	Value
	IsBoolFlag() bool
}

// Flag describes one command-line flag.
type Flag struct {
	Name        string
	Shorthand   string
	Usage       string
	Value       Value
	DefValue    string
	Changed     bool
	NoOptDefVal string
}

// FlagSet holds defined flags and parses argv.
type FlagSet struct {
	name         string
	formal       map[string]*Flag
	ordered      []*Flag
	shorthands   map[byte]*Flag
	args         []string
	interspersed bool
	out          io.Writer
}

// NewFlagSet creates an empty flag set.
func NewFlagSet(name string) *FlagSet {
	return &FlagSet{
		name:         name,
		formal:       make(map[string]*Flag),
		shorthands:   make(map[byte]*Flag),
		interspersed: true,
		out:          os.Stderr,
	}
}

// SetInterspersed controls whether non-flag args may appear between flags.
func (f *FlagSet) SetInterspersed(v bool) { f.interspersed = v }

// Lookup returns the Flag for name, or nil.
func (f *FlagSet) Lookup(name string) *Flag {
	return f.formal[name]
}

// VisitAll visits all flags in definition order.
func (f *FlagSet) VisitAll(fn func(*Flag)) {
	for _, fl := range f.ordered {
		fn(fl)
	}
}

// Args returns non-flag arguments after Parse.
func (f *FlagSet) Args() []string { return f.args }

// SetOutput sets the writer for error messages.
func (f *FlagSet) SetOutput(w io.Writer) {
	if w == nil {
		f.out = os.Stderr
		return
	}
	f.out = w
}

func (f *FlagSet) addFlag(flag *Flag) {
	if flag.Name == "" {
		panic("flag name required")
	}
	if _, ok := f.formal[flag.Name]; ok {
		panic("flag redefined: " + flag.Name)
	}
	f.formal[flag.Name] = flag
	f.ordered = append(f.ordered, flag)
	if flag.Shorthand != "" {
		if len(flag.Shorthand) != 1 {
			panic("shorthand must be one character: " + flag.Name)
		}
		c := flag.Shorthand[0]
		if _, ok := f.shorthands[c]; ok {
			panic(fmt.Sprintf("shorthand -%c redefined", c))
		}
		f.shorthands[c] = flag
	}
}

func (f *FlagSet) VarP(value Value, name, shorthand, usage string) *Flag {
	flag := &Flag{
		Name:      name,
		Shorthand: shorthand,
		Usage:     usage,
		Value:     value,
		DefValue:  value.String(),
	}
	f.addFlag(flag)
	return flag
}

// BoolVar defines a bool flag.
func (f *FlagSet) BoolVar(p *bool, name string, value bool, usage string) {
	f.BoolVarP(p, name, "", value, usage)
}

// BoolVarP defines a bool flag with optional shorthand.
func (f *FlagSet) BoolVarP(p *bool, name, shorthand string, value bool, usage string) {
	flag := f.VarP(newBoolValue(value, p), name, shorthand, usage)
	flag.NoOptDefVal = "true"
}

// StringVar defines a string flag.
func (f *FlagSet) StringVar(p *string, name string, value string, usage string) {
	f.StringVarP(p, name, "", value, usage)
}

// StringVarP defines a string flag with optional shorthand.
func (f *FlagSet) StringVarP(p *string, name, shorthand string, value string, usage string) {
	f.VarP(newStringValue(value, p), name, shorthand, usage)
}

// IntVar defines an int flag.
func (f *FlagSet) IntVar(p *int, name string, value int, usage string) {
	f.IntVarP(p, name, "", value, usage)
}

// IntVarP defines an int flag with optional shorthand.
func (f *FlagSet) IntVarP(p *int, name, shorthand string, value int, usage string) {
	f.VarP(newIntValue(value, p), name, shorthand, usage)
}

func (f *FlagSet) failf(format string, a ...any) error {
	err := fmt.Errorf(format, a...)
	fmt.Fprintln(f.out, err)
	return err
}

// Parse parses arguments. Remaining non-flags go to Args().
func (f *FlagSet) Parse(arguments []string) error {
	f.args = nil
	for i := 0; i < len(arguments); {
		s := arguments[i]
		if len(s) == 0 || s[0] != '-' || len(s) == 1 {
			if !f.interspersed {
				f.args = append(f.args, arguments[i:]...)
				return nil
			}
			f.args = append(f.args, s)
			i++
			continue
		}
		if s == "--" {
			f.args = append(f.args, arguments[i+1:]...)
			return nil
		}
		if s[1] == '-' {
			rest, err := f.parseLong(s, arguments[i+1:])
			if err != nil {
				return err
			}
			arguments = append(arguments[:i], rest...)
			continue
		}
		restArgs, err := f.parseShort(s, arguments[i+1:])
		if err != nil {
			return err
		}
		arguments = append(arguments[:i], restArgs...)
	}
	return nil
}

func (f *FlagSet) parseLong(s string, args []string) ([]string, error) {
	name := s[2:]
	if name == "" || name == "-" {
		return nil, f.failf("bad flag syntax: %s", s)
	}
	if name == "help" {
		return nil, ErrHelp
	}
	value, hasValue := "", false
	if i := strings.IndexByte(name, '='); i >= 0 {
		value = name[i+1:]
		name = name[:i]
		hasValue = true
	}
	flag := f.formal[name]
	if flag == nil {
		return nil, f.failf("unknown flag: --%s", name)
	}
	if hasValue {
		return args, f.setFlag(flag, value)
	}
	if flag.NoOptDefVal != "" {
		return args, f.setFlag(flag, flag.NoOptDefVal)
	}
	if bf, ok := flag.Value.(boolFlag); ok && bf.IsBoolFlag() {
		return args, f.setFlag(flag, "true")
	}
	if len(args) == 0 {
		return nil, f.failf("flag needs an argument: --%s", name)
	}
	return args[1:], f.setFlag(flag, args[0])
}

func (f *FlagSet) parseShort(s string, args []string) ([]string, error) {
	shorthands := s[1:]
	for len(shorthands) > 0 {
		c := shorthands[0]
		shorthands = shorthands[1:]
		if c == 'h' {
			return nil, ErrHelp
		}
		flag := f.shorthands[c]
		if flag == nil {
			return nil, f.failf("unknown shorthand flag: %q in -%s", c, s[1:])
		}
		if len(shorthands) > 0 && shorthands[0] == '=' {
			return args, f.setFlag(flag, shorthands[1:])
		}
		if flag.NoOptDefVal != "" {
			if err := f.setFlag(flag, flag.NoOptDefVal); err != nil {
				return nil, err
			}
			continue
		}
		if bf, ok := flag.Value.(boolFlag); ok && bf.IsBoolFlag() {
			if err := f.setFlag(flag, "true"); err != nil {
				return nil, err
			}
			continue
		}
		if len(shorthands) > 0 {
			return args, f.setFlag(flag, shorthands)
		}
		if len(args) == 0 {
			return nil, f.failf("flag needs an argument: %q in -%s", c, s[1:])
		}
		return args[1:], f.setFlag(flag, args[0])
	}
	return args, nil
}

func (f *FlagSet) setFlag(flag *Flag, value string) error {
	if err := flag.Value.Set(value); err != nil {
		return f.failf("invalid argument %q for --%s: %v", value, flag.Name, err)
	}
	flag.Changed = true
	return nil
}

// SortedNames returns flag names sorted for stable help (optional).
func (f *FlagSet) SortedNames() []string {
	names := make([]string, 0, len(f.formal))
	for n := range f.formal {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// --- value types ---

type boolValue bool

func newBoolValue(val bool, p *bool) *boolValue {
	*p = val
	return (*boolValue)(p)
}
func (b *boolValue) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return errors.New("must be true or false")
	}
	*b = boolValue(v)
	return nil
}
func (b *boolValue) Type() string   { return "bool" }
func (b *boolValue) String() string { return strconv.FormatBool(bool(*b)) }
func (b *boolValue) IsBoolFlag() bool { return true }

type stringValue string

func newStringValue(val string, p *string) *stringValue {
	*p = val
	return (*stringValue)(p)
}
func (s *stringValue) Set(val string) error {
	*s = stringValue(val)
	return nil
}
func (s *stringValue) Type() string   { return "string" }
func (s *stringValue) String() string { return string(*s) }

type intValue int

func newIntValue(val int, p *int) *intValue {
	*p = val
	return (*intValue)(p)
}
func (i *intValue) Set(s string) error {
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return errors.New("must be an integer")
	}
	*i = intValue(v)
	return nil
}
func (i *intValue) Type() string   { return "int" }
func (i *intValue) String() string { return strconv.Itoa(int(*i)) }
