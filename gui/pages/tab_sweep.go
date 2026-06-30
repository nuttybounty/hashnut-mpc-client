package pages

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// buildSweepGasTab 回收手续费 Tab
func (p *MainPage) buildSweepGasTab() fyne.CanvasObject {
	currentChain, _ := p.svc.GetCurrentChain()
	if currentChain != "" {
		_ = p.svc.FetchSplitWallets(currentChain)
	}
	activeSplitters, _ := p.svc.ListActiveSplitWallets()

	splitterOptions := make([]string, len(activeSplitters))
	for i, sw := range activeSplitters {
		label := truncAddr(sw.Address)
		if sw.Alias != "" {
			label = fmt.Sprintf("%s (%s)", sw.Alias, truncAddr(sw.Address))
		}
		splitterOptions[i] = label
	}
	splitterSelect := widget.NewSelect(splitterOptions, nil)
	if len(splitterOptions) > 0 {
		splitterSelect.SetSelectedIndex(0)
	}

	logArea := widget.NewMultiLineEntry()
	logArea.Wrapping = fyne.TextWrapWord
	logArea.TextStyle = fyne.TextStyle{Monospace: true}

	appendLog := func(msg string) {
		fyne.Do(func() {
			logArea.SetText(logArea.Text + msg + "\n")
		})
	}

	var sweepBtn *widget.Button
	sweepBtn = widget.NewButton("回收手续费", func() {
		if splitterSelect.SelectedIndex() < 0 {
			dialog.ShowError(fmt.Errorf("请选择分账合约"), p.window)
			return
		}
		sw := activeSplitters[splitterSelect.SelectedIndex()]

		sweepBtn.Disable()
		logArea.SetText("")
		appendLog(fmt.Sprintf("正在查询 %s 的收款地址和 manager...", truncAddr(sw.Address)))

		go func() {
			defer fyne.Do(func() { sweepBtn.Enable() })
			ctx := context.Background()
			if err := p.svc.SweepGas(ctx, sw.Address, appendLog); err != nil {
				appendLog(fmt.Sprintf("ERROR: %v", err))
			}
		}()
	})

	return container.NewBorder(
		container.NewVBox(
			widget.NewForm(
				widget.NewFormItem("分账合约", splitterSelect),
			),
			container.NewHBox(sweepBtn),
			widget.NewSeparator(),
		),
		nil, nil, nil,
		container.NewScroll(logArea),
	)
}
