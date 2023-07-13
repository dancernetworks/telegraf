// +build windows

package main

import (
	"log"
	"os"
	"runtime"

	"github.com/influxdata/telegraf/logger"
	"github.com/kardianos/service"
)

func run(inputFilters, outputFilters []string) {
	// Register the eventlog logging target for windows.
	logger.RegisterEventLogger(*fServiceName)

	if runtime.GOOS == "windows" && windowsRunAsService() {
		runAsWindowsService(
			inputFilters,
			outputFilters,
		)
	} else {
		stop = make(chan struct{})
		reloadLoop(
			inputFilters,
			outputFilters,
		)
	}
}

type program struct {
	inputFilters  []string
	outputFilters []string
}

func (p *program) Start(s service.Service) error {
	log.Printf("I! Service start called")

	// Create a channel to signal the completion of the run() method
	done := make(chan bool)

	// Start the run() method in a goroutine
	go func() {
		defer close(done) // Signal that the run() method has completed when the goroutine exits
		log.Printf("I! Calling run()")
		p.run()
	}()

	log.Printf("I! Start method returned")

	// Return immediately without waiting for the run() method to complete
	return nil
}

func (p *program) run() {
	log.Printf("I! Start run()")

	time.Sleep(2 * time.Minute)

	stop = make(chan struct{})
	reloadLoop(
		p.inputFilters,
		p.outputFilters,
	)
	log.Printf("I! Run finished.")
}

func (p *program) Stop(s service.Service) error {
	close(stop)
	return nil
}

func runAsWindowsService(inputFilters, outputFilters []string) {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" { // Should never happen
		programFiles = "C:\\Program Files"
	}
	svcConfig := &service.Config{
		Name:        *fServiceName,
		DisplayName: *fServiceDisplayName,
		Description: "Collects data using a series of plugins and publishes it to " +
			"another series of plugins.",
		Arguments: []string{"--config", programFiles + "\\Telegraf\\telegraf.conf"},
	}

	prg := &program{
		inputFilters:  inputFilters,
		outputFilters: outputFilters,
	}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal("E! " + err.Error())
	}
	// Handle the --service flag here to prevent any issues with tooling that
	// may not have an interactive session, e.g. installing from Ansible.
	if *fService != "" {
		if len(fConfigs) > 0 {
			svcConfig.Arguments = []string{}
		}
		for _, fConfig := range fConfigs {
			svcConfig.Arguments = append(svcConfig.Arguments, "--config", fConfig)
		}

		for _, fConfigDirectory := range fConfigDirs {
			svcConfig.Arguments = append(svcConfig.Arguments, "--config-directory", fConfigDirectory)
		}

		//set servicename to service cmd line, to have a custom name after relaunch as a service
		svcConfig.Arguments = append(svcConfig.Arguments, "--service-name", *fServiceName)

		err := service.Control(s, *fService)
		if err != nil {
			log.Fatal("E! " + err.Error())
		}
		os.Exit(0)
	} else {
		logger.SetupLogging(logger.LogConfig{LogTarget: logger.LogTargetEventlog})
		err = s.Run()

		if err != nil {
			log.Println("E! " + err.Error())
		}
	}
}

// Return true if Telegraf should create a Windows service.
func windowsRunAsService() bool {
	if *fService != "" {
		return true
	}

	if *fRunAsConsole {
		return false
	}

	return !service.Interactive()
}
