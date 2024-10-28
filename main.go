package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/yourzinc/elbcli/iptrace"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const listHeight = 20

var (
	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	helpStyle         = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
	quitTextStyle     = lipgloss.NewStyle().Margin(1, 0, 2, 4)
)

type item string

func (i item) FilterValue() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

type fetchALBsMsg struct {
	albNames []string
	err      error
}

type fetchIPTraceMsg struct {
	ipTrace []iptrace.OutputData
	err     error
}

type model struct {
	list         list.Model
	albList      list.Model
	choice       string
	quitting     bool
	showingALBs  bool
	ipTrace      []iptrace.OutputData
	showingTrace bool
}

func (m model) Init() tea.Cmd {
	return nil
}

func fetchALBsCmd() tea.Cmd {
	return func() tea.Msg {
		albNames, err := iptrace.FetchALBs()
		return fetchALBsMsg{albNames: albNames, err: err}
	}
}

func fetchIPhistoryCmd(albName string) tea.Cmd {
	return func() tea.Msg {
		ipTrace, err := iptrace.FetchIPhistory(albName)
		return fetchIPTraceMsg{ipTrace: ipTrace, err: err}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			if !m.showingALBs && !m.showingTrace {
				i, ok := m.list.SelectedItem().(item)
				if ok {
					m.choice = string(i)
					if m.choice == "IP Address Tracing" {
						return m, fetchALBsCmd()
					}
				}
			} else if m.showingALBs && !m.showingTrace {
				i, ok := m.albList.SelectedItem().(item)
				if ok {
					albName := string(i)
					m.showingTrace = true
					return m, fetchIPhistoryCmd(albName)
				}
			}
		}
	case fetchALBsMsg:
		if msg.err != nil {
			m.choice = "Error fetching ALBs"
		} else {
			albItems := make([]list.Item, len(msg.albNames))
			for i, name := range msg.albNames {
				albItems[i] = item(name)
			}

			m.albList = list.New(albItems, itemDelegate{}, 20, listHeight)
			m.albList.Title = "Select an ALB"
			m.showingALBs = true
		}
		return m, nil

	case fetchIPTraceMsg:
		if msg.err == nil {
			m.ipTrace = msg.ipTrace
		}
		m.showingTrace = true
		return m, nil
	}

	var cmd tea.Cmd
	if m.showingTrace {
		return m, nil
	}
	if m.showingALBs {
		m.albList, cmd = m.albList.Update(msg)
	} else {
		m.list, cmd = m.list.Update(msg)
	}
	return m, cmd
}

func (m model) View() string {
	if m.quitting {
		return quitTextStyle.Render(":)")
	}
	if m.showingTrace {
		traceView := "IP Address History:\n\n"
		for i, entry := range m.ipTrace {
			traceView += fmt.Sprintf("%d. %s - %s\n", i+1, entry.EventTime.Format(time.RFC3339), entry.PrivateIPAddress)
		}
		return traceView + "\nPress 'q' to quit."
	}
	if m.showingALBs {
		return m.albList.View()
	}
	if m.choice == "IP Address Tracing" && !m.showingALBs {
		return "Fetching ALB names...\n"
	}
	if m.choice == "LCU Cost Analyzer" {
		return quitTextStyle.Render("It will be updated.")
	}
	return "\n" + m.list.View()
}

func main() {

	items := []list.Item{
		item("IP Address Tracing"),
		item("LCU Cost Analyzer"),
	}

	const defaultWidth = 20

	l := list.New(items, itemDelegate{}, defaultWidth, listHeight)
	l.Title = "Choose an option below:"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	m := model{list: l}

	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
