package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/google/renameio"

	"github.com/netauth/localizer/pkg/maps/base"
)

var (
	minUID = pflag.Int("min-uid", 2000, "Minimum UID number to accept")
	minGID = pflag.Int("min-gid", 2000, "Minimum GID number to accept")

	defShell = pflag.String("shell", "/bin/nologin", "Default shell to use if none is provided in the directory")

	baseDir = pflag.String("base", "/etc", "Base directory for files")
	cfgfile = pflag.String("config", "", "Config file to use")

	log hclog.Logger
)

func main() {
	log = hclog.L().Named("localizer")
	hclog.SetDefault(log)

	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	if *cfgfile != "" {
		viper.SetConfigFile(*cfgfile)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("/etc/netauth/")
		viper.AddConfigPath("$HOME/.netauth")
		viper.AddConfigPath(".")
	}
	if err := viper.ReadInConfig(); err != nil {
		log.Error("Error reading config:", "error", err)
		os.Exit(1)
	}

	// Set up the base identity map structures.
	baseIdentity := base.New()
	baseIdentity.SetBaseDir(*baseDir)
	baseIdentity.SetLogger(log.Named("base-identity"))
	baseIdentity.SetMinUID(int32(*minUID))
	baseIdentity.SetMinGID(int32(*minGID))
	baseIdentity.SetFallbackShell(*defShell)

	// Load the identity maps that are on disk.
	if err := baseIdentity.Load(); err != nil {
		log.Error("Error loading maps from disk", "error", err)
		os.Exit(1)
	}

	// Connect to and load the updated information from NetAuth.
	ctx := context.Background()

	if err := baseIdentity.ConnectNetAuth(); err != nil {
		log.Error("Error connecting to NetAuth", "error", err)
		os.Exit(1)
	}
	if err := baseIdentity.LoadNetAuthData(ctx); err != nil {
		log.Error("Error loading data from NetAuth", "error", err)
		os.Exit(1)
	}

	// Merge remote information with base maps
	baseIdentity.MergePasswd()
	baseIdentity.MergeGroup()
	log.Info("baseIdentity", "passwd", baseIdentity.FetchPasswd().String())
	log.Info("baseIdentity", "group", baseIdentity.FetchGroup().String())

	if err := renameio.WriteFile(filepath.Join(*baseDir, "passwd"), baseIdentity.PasswdBytes(), 0644); err != nil {
		log.Error("Error writing passwd", "error", err)
		os.Exit(2)
	}

	if err := renameio.WriteFile(filepath.Join(*baseDir, "group"), baseIdentity.GroupBytes(), 0644); err != nil {
		log.Error("Error writing group", "error", err)
		os.Exit(2)
	}
}
