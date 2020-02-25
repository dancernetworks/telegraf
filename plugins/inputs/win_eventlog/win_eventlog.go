//+build windows

//revive:disable-next-line:var-naming
// Package win_eventlog Input plugin to collect Windows Event Log messages
package win_eventlog

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
	"golang.org/x/sys/windows"
)

var sampleConfig = `
  ## Telegraf should have Administrator permissions to subscribe for some Windows Events channels
  ## (System log, for example)

  ## LCID (Locale ID) for event rendering
  ## 1033 to force English language
  ## 0 to use default Windows locale
  # locale = 0

  ## Name of eventlog, used only if xpath_query is empty
  ## Example: "Application"
  # eventlog_name = ""

  ## xpath_query can be in defined short form like "Event/System[EventID=999]"
  ## or you can form a XML Query. Refer to the Consuming Events article:
  ## https://docs.microsoft.com/en-us/windows/win32/wes/consuming-events
  ## XML query is the recommended form, because it is most flexible
  ## You can create or debug XML Query by creating Custom View in Windows Event Viewer
  ## and then copying resulting XML here
  xpath_query = '''
  <QueryList>
    <Query Id="0" Path="Security">
      <Select Path="Security">*</Select>
      <Suppress Path="Security">*[System[( (EventID &gt;= 5152 and EventID &lt;= 5158) or EventID=5379 or EventID=4672)]]</Suppress>
    </Query>
    <Query Id="1" Path="Application">
      <Select Path="Application">*[System[(Level &lt; 4)]]</Select>
    </Query>
    <Query Id="2" Path="Windows PowerShell">
      <Select Path="Windows PowerShell">*[System[(Level &lt; 4)]]</Select>
    </Query>
    <Query Id="3" Path="System">
      <Select Path="System">*</Select>
    </Query>
    <Query Id="4" Path="Setup">
      <Select Path="Setup">*</Select>
    </Query>
  </QueryList>
  '''

  ## System field names:
  ##   "Source", "EventID", "Version", "Level", "Task", "Opcode", "Keywords", "TimeCreated",
  ##   "EventRecordID", "ActivityID", "RelatedActivityID", "ProcessID", "ThreadID", "ProcessName",
  ##   "Channel", "Computer", "UserID", "UserName", "Message", "LevelText", "TaskText", "OpcodeText"

  ## In addition to System, Data fields can be unrolled from additional XML nodes in event.
  ## Human-readable representation of those nodes is formatted into event Message field,
  ## but XML is more machine-parsable

  # Process UserData XML to fields, if this node exists in Event XML
  process_userdata = true

  # Process EventData XML to fields, if this node exists in Event XML
  process_eventdata = true

  ## Separator character to use for unrolled XML Data field names
  separator = "_"

  ## Get only first line of Message field. For most events first line is usually more than enough
  only_first_line_of_message = true

  ## Parse timestamp from TimeCreated.SystemTime event field.
  ## Will default to current time of telegraf processing on parsing error or if set to false
  timestamp_from_event = true

  ## Fields to include as tags. Globbing supported ("Level*" for both "Level" and "LevelText")
  event_tags = ["Source", "EventID", "Level", "LevelText", "Task", "TaskText", "Opcode", "OpcodeText", "Keywords", "Channel", "Computer"]

  ## Default list of fields to send. All fields are sent by default. Globbing supported
  event_fields = ["*"]

  ## Fields to exclude. Also applied to data fields. Globbing supported
  exclude_fields = ["TimeCreated", "Binary", "Data_Address*"]

  ## Skip those tags or fields if their value is empty or equals to zero. Globbing supported
  exclude_empty = ["*ActivityID", "UserID"]
`

// WinEventLog config
type WinEventLog struct {
	Locale                 uint32   `toml:"locale"`
	EventlogName           string   `toml:"eventlog_name"`
	Query                  string   `toml:"xpath_query"`
	ProcessUserData        bool     `toml:"process_userdata"`
	ProcessEventData       bool     `toml:"process_eventdata"`
	Separator              string   `toml:"separator"`
	OnlyFirstLineOfMessage bool     `toml:"only_first_line_of_message"`
	TimeStampFromEvent     bool     `toml:"timestamp_from_event"`
	EventTags              []string `toml:"event_tags"`
	EventFields            []string `toml:"event_fields"`
	ExcludeFields          []string `toml:"exclude_fields"`
	ExcludeEmpty           []string `toml:"exclude_empty"`
	subscription           EvtHandle
	buf                    []byte
	Log                    telegraf.Logger
}

var bufferSize = 1 << 14

var description = "Input plugin to collect Windows Event Log messages"

// Description for win_eventlog
func (w *WinEventLog) Description() string {
	return description
}

// SampleConfig for win_eventlog
func (w *WinEventLog) SampleConfig() string {
	return sampleConfig
}

// Gather Windows Event Log entries
func (w *WinEventLog) Gather(acc telegraf.Accumulator) error {

	var err error
	if w.subscription == 0 {
		w.subscription, err = w.evtSubscribe(w.EventlogName, w.Query)
		if err != nil {
			return fmt.Errorf("Windows Event Log subscription error: %v", err.Error())
		}
	}
	w.Log.Debug("Subscription handle id:", w.subscription)

loop:
	for {
		events, err := w.fetchEvents(w.subscription)
		if err != nil {
			switch {
			case err == ERROR_NO_MORE_ITEMS:
				break loop
			case err != nil:
				w.Log.Error("Error getting events:", err.Error())
				return err
			}
		}

		for _, event := range events {
			eventTime := event.TimeCreated.SystemTime

			timeStamp, err := time.Parse(time.RFC3339Nano, fmt.Sprintf("%v", eventTime))
			if err != nil {
				w.Log.Warnf("Error parsing timestamp %q: %v", eventTime, err)
				timeStamp = time.Now()
			}

			description := createDescriptionFromEvent(event)

			acc.AddFields("win_event",
				map[string]interface{}{
					"record_id":     event.EventRecordID,
					"event_id":      event.EventID,
					"level":         event.Level,
					"message":       event.Message,
					"description":   description,
					"source":        event.Source.Name,
					"created":       eventTime,
				}, map[string]string{
					"eventlog_name": event.Channel,
				}, timeStamp)
		}
	}

	return nil
}

func createDescriptionFromEvent(event Event) (string) {
	var fieldsUsage = map[string]int{}
	fieldsEventData, _ := UnrollXMLFields(event.EventData.InnerXML, fieldsUsage, "_")

	var eventDataValues []string
	for _, xmlField := range fieldsEventData {
		eventDataValues = append(eventDataValues, xmlField.Value)
	}

	description := strings.Join(eventDataValues, "|")

	crlfRe := regexp.MustCompile(`[\r\n]+`)
	description = crlfRe.ReplaceAllString(description, "|")

	return description
}

func (w *WinEventLog) shouldExclude(field string) (should bool) {
	for _, excludePattern := range w.ExcludeFields {
		// Check if field name matches excluded list
		if matched, _ := filepath.Match(excludePattern, field); matched {
			return true
		}
	}
	return false
}

func (w *WinEventLog) shouldProcessField(field string) (should bool, list string) {
	for _, pattern := range w.EventTags {
		if matched, _ := filepath.Match(pattern, field); matched {
			// Tags are not excluded
			return true, "tags"
		}
	}

	for _, pattern := range w.EventFields {
		if matched, _ := filepath.Match(pattern, field); matched {
			if w.shouldExclude(field) {
				return false, "excluded"
			}
			return true, "fields"
		}
	}
	return false, "excluded"
}

func (w *WinEventLog) shouldExcludeEmptyField(field string, fieldType string, fieldValue interface{}) (should bool) {
	for _, pattern := range w.ExcludeEmpty {
		if matched, _ := filepath.Match(pattern, field); matched {
			switch fieldType {
			case "string":
				return len(fieldValue.(string)) < 1
			case "int":
				return fieldValue.(int) == 0
			case "uint32":
				return fieldValue.(uint32) == 0
			}
		}
	}
	return false
}

func (w *WinEventLog) evtSubscribe(logName, xquery string) (EvtHandle, error) {
	var logNamePtr, xqueryPtr *uint16

	sigEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(sigEvent)

	logNamePtr, err = syscall.UTF16PtrFromString(logName)
	if err != nil {
		return 0, err
	}

	xqueryPtr, err = syscall.UTF16PtrFromString(xquery)
	if err != nil {
		return 0, err
	}

	subsHandle, err := _EvtSubscribe(0, uintptr(sigEvent), logNamePtr, xqueryPtr,
		0, 0, 0, EvtSubscribeToFutureEvents)
	if err != nil {
		return 0, err
	}

	return subsHandle, nil
}

func (w *WinEventLog) fetchEventHandles(subsHandle EvtHandle) ([]EvtHandle, error) {
	var eventsNumber uint32
	var evtReturned uint32

	eventsNumber = 5

	eventHandles := make([]EvtHandle, eventsNumber)

	err := _EvtNext(subsHandle, eventsNumber, &eventHandles[0], 0, 0, &evtReturned)
	if err != nil {
		if err == ERROR_INVALID_OPERATION && evtReturned == 0 {
			return nil, ERROR_NO_MORE_ITEMS
		}
		return nil, err
	}

	return eventHandles[:evtReturned], nil
}

func (w *WinEventLog) fetchEvents(subsHandle EvtHandle) ([]Event, error) {
	var events []Event

	eventHandles, err := w.fetchEventHandles(subsHandle)
	if err != nil {
		return nil, err
	}

	for _, eventHandle := range eventHandles {
		if eventHandle != 0 {
			event, err := w.renderEvent(eventHandle)
			if err == nil {
				// w.Log.Debugf("Got event: %v", event)
				events = append(events, event)
			}
		}
	}

	for i := 0; i < len(eventHandles); i++ {
		err := _EvtClose(eventHandles[i])
		if err != nil {
			return events, err
		}
	}
	return events, nil
}

func (w *WinEventLog) renderEvent(eventHandle EvtHandle) (Event, error) {
	var bufferUsed, propertyCount uint32

	event := Event{}
	err := _EvtRender(0, eventHandle, EvtRenderEventXml, uint32(len(w.buf)), &w.buf[0], &bufferUsed, &propertyCount)
	if err != nil {
		return event, err
	}

	eventXML, err := DecodeUTF16(w.buf[:bufferUsed])
	if err != nil {
		return event, err
	}
	err = xml.Unmarshal([]byte(eventXML), &event)
	if err != nil {
		// We can return event without most text values,
		// that way we will not loose information
		// This can happen when processing Forwarded Events
		return event, nil
	}

	publisherHandle, err := openPublisherMetadata(0, event.Source.Name, w.Locale)
	if err != nil {
		return event, nil
	}
	defer _EvtClose(publisherHandle)

	// Populating text values
	keywords, err := formatEventString(EvtFormatMessageKeyword, eventHandle, publisherHandle)
	if err == nil {
		event.Keywords = keywords
	}
	message, err := formatEventString(EvtFormatMessageEvent, eventHandle, publisherHandle)
	if err == nil {
		crlfRe := regexp.MustCompile(`[\r\n]+`)
		message = strings.TrimSpace(message)
		message = crlfRe.ReplaceAllString(message, "|")
		event.Message = message
	}
	level, err := formatEventString(EvtFormatMessageLevel, eventHandle, publisherHandle)
	if err == nil {
		event.LevelText = level
	}
	task, err := formatEventString(EvtFormatMessageTask, eventHandle, publisherHandle)
	if err == nil {
		event.TaskText = task
	}
	opcode, err := formatEventString(EvtFormatMessageOpcode, eventHandle, publisherHandle)
	if err == nil {
		event.OpcodeText = opcode
	}
	return event, nil
}

func formatEventString(
	messageFlag EvtFormatMessageFlag,
	eventHandle EvtHandle,
	publisherHandle EvtHandle,
) (string, error) {
	var bufferUsed uint32
	err := _EvtFormatMessage(publisherHandle, eventHandle, 0, 0, 0, messageFlag,
		0, nil, &bufferUsed)
	if err != nil && err != ERROR_INSUFFICIENT_BUFFER {
		return "", err
	}

	bufferUsed *= 2
	buffer := make([]byte, bufferUsed)
	bufferUsed = 0

	err = _EvtFormatMessage(publisherHandle, eventHandle, 0, 0, 0, messageFlag,
		uint32(len(buffer)/2), &buffer[0], &bufferUsed)
	bufferUsed *= 2
	if err != nil {
		return "", err
	}

	result, err := DecodeUTF16(buffer[:bufferUsed])
	if err != nil {
		return "", err
	}

	var out string
	if messageFlag == EvtFormatMessageKeyword {
		// Keywords are returned as array of a zero-terminated strings
		splitZero := func(c rune) bool { return c == '\x00' }
		eventKeywords := strings.FieldsFunc(string(result), splitZero)
		// So convert them to comma-separated string
		out = strings.Join(eventKeywords, ",")
	} else {
		result := bytes.Trim(result, "\x00")
		out = string(result)
	}
	return out, nil
}

// openPublisherMetadata opens a handle to the publisher's metadata. Close must
// be called on returned EvtHandle when finished with the handle.
func openPublisherMetadata(
	session EvtHandle,
	publisherName string,
	lang uint32,
) (EvtHandle, error) {
	p, err := syscall.UTF16PtrFromString(publisherName)
	if err != nil {
		return 0, err
	}

	h, err := _EvtOpenPublisherMetadata(session, p, nil, lang, 0)
	if err != nil {
		return 0, err
	}

	return h, nil
}

func init() {
	inputs.Add("win_eventlog", func() telegraf.Input {
		return &WinEventLog{
			buf:                    make([]byte, bufferSize),
			ProcessUserData:        true,
			ProcessEventData:       true,
			Separator:              "_",
			OnlyFirstLineOfMessage: true,
			TimeStampFromEvent:     true,
			EventTags:              []string{"Source", "EventID", "Level", "LevelText", "Keywords", "Channel", "Computer"},
			EventFields:            []string{"*"},
			ExcludeEmpty:           []string{"Task", "Opcode", "*ActivityID", "UserID"},
		}
	})
}
