package cli

import (
	"fmt"
	"os"
)

// Command is a minimal root command (no subcommands).
type Command struct {
	Use   string
	Short string
	Long  string
	Run   func(cmd *Command, args []string)

	flags     *FlagSet
	usageFunc func(*Command) error
}

// Flags returns the command flag set, creating it on first use.
func (c *Command) Flags() *FlagSet {
	if c.flags == nil {
		c.flags = NewFlagSet(c.Use)
	}
	return c.flags
}

// SetUsageFunc sets a custom usage/help printer.
func (c *Command) SetUsageFunc(fn func(*Command) error) {
	c.usageFunc = fn
}

// Help prints usage via usageFunc or a short fallback.
func (c *Command) Help() error {
	if c.usageFunc != nil {
		return c.usageFunc(c)
	}
	if c.Long != "" {
		fmt.Println(c.Long)
	} else if c.Short != "" {
		fmt.Println(c.Short)
	}
	fmt.Printf("Usage:\n  %s [flags]\n", c.Use)
	return nil
}

// Execute parses os.Args and runs the command.
func (c *Command) Execute() error {
	fs := c.Flags()
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == ErrHelp {
			_ = c.Help()
			return nil
		}
		return err
	}
	if c.Run != nil {
		c.Run(c, fs.Args())
	}
	return nil
}
