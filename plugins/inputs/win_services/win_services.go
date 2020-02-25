// +build windows

package win_services

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/filter"
	"github.com/influxdata/telegraf/plugins/inputs"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type ServiceErr struct {
	Message string
	Service string
	Err     error
}

func (e *ServiceErr) Error() string {
	return fmt.Sprintf("%s: '%s': %v", e.Message, e.Service, e.Err)
}

func IsPermission(err error) bool {
	if err, ok := err.(*ServiceErr); ok {
		return os.IsPermission(err.Err)
	}
	return false
}

// WinService provides interface for svc.Service
type WinService interface {
	Close() error
	Config() (mgr.Config, error)
	Query() (svc.Status, error)
}

// ManagerProvider sets interface for acquiring manager instance, like mgr.Mgr
type ManagerProvider interface {
	Connect() (WinServiceManager, error)
}

// WinServiceManager provides interface for mgr.Mgr
type WinServiceManager interface {
	Disconnect() error
	OpenService(name string) (WinService, error)
	ListServices() ([]string, error)
}

// WinSvcMgr is wrapper for mgr.Mgr implementing WinServiceManager interface
type WinSvcMgr struct {
	realMgr *mgr.Mgr
}

func (m *WinSvcMgr) Disconnect() error {
	return m.realMgr.Disconnect()
}

func (m *WinSvcMgr) OpenService(name string) (WinService, error) {
	return m.realMgr.OpenService(name)
}
func (m *WinSvcMgr) ListServices() ([]string, error) {
	return m.realMgr.ListServices()
}

// MgProvider is an implementation of WinServiceManagerProvider interface returning WinSvcMgr
type MgProvider struct {
}

func (rmr *MgProvider) Connect() (WinServiceManager, error) {
	scmgr, err := mgr.Connect()
	if err != nil {
		return nil, err
	} else {
		return &WinSvcMgr{scmgr}, nil
	}
}

var sampleConfig = `
  ## Names of the services to monitor. Leave empty to monitor all the available services on the host. Globs accepted.
  service_names = [
    "LanmanServer",
	"TermService",
	"Win*",
  ]
`

var description = "Input plugin to report Windows services info."

//WinServices is an implementation if telegraf.Input interface, providing info about Windows Services
type WinServices struct {
	Log telegraf.Logger

	ServiceNames []string `toml:"service_names"`
	mgrProvider  ManagerProvider

	servicesFilter filter.Filter
}

type ServiceInfo struct {
	ServiceName string
	DisplayName string
	State       int
	StartUpMode int
}

func (m *WinServices) Init() error {
	var err error
	m.servicesFilter, err = filter.NewIncludeExcludeFilter(m.ServiceNames, nil)
	if err != nil {
		return err
	}

	return nil
}

func (m *WinServices) Description() string {
	return description
}

func (m *WinServices) SampleConfig() string {
	return sampleConfig
}

func (m *WinServices) Gather(acc telegraf.Accumulator) error {
	scmgr, err := m.mgrProvider.Connect()
	if err != nil {
		return fmt.Errorf("Could not open service manager: %s", err)
	}
	defer scmgr.Disconnect()

	serviceNames, err := m.listServices(scmgr)
	if err != nil {
		return err
	}

	for _, srvName := range serviceNames {
		service, err := m.collectServiceInfo(scmgr, srvName)
		if err != nil {
			if IsPermission(err) {
				m.Log.Debug(err.Error())
			} else {
				m.Log.Error(err.Error())
			}
			continue
		}

		tags := map[string]string{
			"service_name": service.ServiceName,
		}

		fields := map[string]interface{}{
			"state":        service.State,
			"startup_mode": service.StartUpMode,
		}

		//display name could be empty, but still valid service
		if len(service.DisplayName) > 0 {
			fields["display_name"] = service.DisplayName
		}

		acc.AddFields("win_services", fields, tags)
	}

	return nil
}

// listServices returns a list of services to gather.
func (m *WinServices) listServices(scmgr WinServiceManager) ([]string, error) {
	names, err := scmgr.ListServices()
	if err != nil {
		return nil, fmt.Errorf("Could not list services: %s", err)
	}

	var services []string
	for _, n := range names {
		if m.servicesFilter.Match(n) {
			services = append(services, n)
		}
	}

	return services, nil
}

// collectServiceInfo gathers info about a service.
func (m *WinServices) collectServiceInfo(scmgr WinServiceManager, serviceName string) (*ServiceInfo, error) {
	srv, err := scmgr.OpenService(serviceName)
	if err != nil {
		return nil, &ServiceErr{
			Message: "could not open service",
			Service: serviceName,
			Err:     err,
		}
	}
	defer srv.Close()

	srvStatus, err := srv.Query()
	if err != nil {
		return nil, &ServiceErr{
			Message: "could not query service",
			Service: serviceName,
			Err:     err,
		}
	}

	displayName, startType, err := DisplayNameStartType(srv.(*mgr.Service))
	if err != nil {
		m.Log.Warnf("Could not get config of service %s: %s", serviceName, err)
		displayName = fmt.Sprintf("Could not get config of service %s", serviceName)
	}

	serviceInfo := &ServiceInfo{
		ServiceName: serviceName,
		DisplayName: displayName,
		StartUpMode: int(startType),
		State:       int(srvStatus.State),
	}
	return serviceInfo, nil
}

func DisplayNameStartType(s *mgr.Service) (string, uint32, error) {
	var p *windows.QUERY_SERVICE_CONFIG
	n := uint32(1024)
	for {
		b := make([]byte, n)
		p = (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&b[0]))
		err := windows.QueryServiceConfig(s.Handle, p, n, &n)
		if err == nil {
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_INSUFFICIENT_BUFFER {
			return "", 0, err
		}
		if n <= uint32(len(b)) {
			return "", 0, err
		}
	}

	return windows.UTF16PtrToString(p.DisplayName), p.StartType, nil
}

func init() {
	inputs.Add("win_services", func() telegraf.Input {
		return &WinServices{
			mgrProvider: &MgProvider{},
		}
	})
}
