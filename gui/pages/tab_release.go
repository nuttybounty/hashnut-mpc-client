package pages

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// buildReleaseTab 资金提现 Tab
func (p *MainPage) buildReleaseTab() fyne.CanvasObject {
	currentChain, _ := p.svc.GetCurrentChain()
	if currentChain != "" {
		_ = p.svc.FetchSplitWallets(currentChain)
	}
	activeSplitters, _ := p.svc.ListActiveSplitWallets()
	tokens, _ := p.svc.ListTokensByChain(currentChain)

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

	tokenOptions := make([]string, len(tokens))
	for i, t := range tokens {
		tokenOptions[i] = fmt.Sprintf("%s (%s)", t.Name, truncAddr(t.Contract))
	}
	tokenSelect := widget.NewSelect(tokenOptions, nil)
	if len(tokenOptions) > 0 {
		tokenSelect.SetSelectedIndex(0)
	}

	balanceLabel := widget.NewLabel("")
	balanceLabel.Wrapping = fyne.TextWrapWord

	logArea := widget.NewMultiLineEntry()
	logArea.Wrapping = fyne.TextWrapWord
	logArea.TextStyle = fyne.TextStyle{Monospace: true}

	appendLog := func(msg string) {
		fyne.Do(func() {
			logArea.SetText(logArea.Text + msg + "\n")
		})
	}

	// 查询可提取余额
	queryBtn := widget.NewButton("查询余额", func() {
		if splitterSelect.SelectedIndex() < 0 || tokenSelect.SelectedIndex() < 0 {
			dialog.ShowError(fmt.Errorf("请选择分账合约和 Token"), p.window)
			return
		}
		splitter := activeSplitters[splitterSelect.SelectedIndex()].Address
		token := tokens[tokenSelect.SelectedIndex()].Contract

		go func() {
			balance, err := p.svc.QueryReleasableBalance(splitter, token)
			if err != nil {
				fyne.Do(func() { balanceLabel.SetText(fmt.Sprintf("查询失败: %v", err)) })
				return
			}
			fyne.Do(func() { balanceLabel.SetText(fmt.Sprintf("可提现余额: %s (最小单位)", balance)) })
		}()
	})

	var releaseBtn *widget.Button
	releaseBtn = widget.NewButton("提现", func() {
		if splitterSelect.SelectedIndex() < 0 {
			dialog.ShowError(fmt.Errorf("请选择分账合约"), p.window)
			return
		}
		if tokenSelect.SelectedIndex() < 0 {
			dialog.ShowError(fmt.Errorf("请选择 Token"), p.window)
			return
		}
		splitter := activeSplitters[splitterSelect.SelectedIndex()].Address
		token := tokens[tokenSelect.SelectedIndex()].Contract

		releaseBtn.Disable()
		go func() {
			est, err := p.svc.EstimateReleaseFee(splitter, token)
			if err != nil {
				fyne.Do(func() {
					releaseBtn.Enable()
					dialog.ShowError(fmt.Errorf("费用评估失败: %v", err), p.window)
				})
				return
			}

			detail := fmt.Sprintf(
				"链: %s\n\n"+
					"费用明细:\n"+
					"  预估手续费: %s %s\n"+
					"  预估手续费 (×1.5): %s %s\n\n"+
					"当前钱包余额: %s %s",
				est.Chain,
				est.EstimatedFee, est.NativeSymbol,
				est.TotalFee, est.NativeSymbol,
				est.WalletBalance, est.NativeSymbol,
			)

			if !est.Sufficient {
				detail += "\n\n余额不足，请充值后再试。"
			}

			fyne.Do(func() {
				if !est.Sufficient {
					releaseBtn.Enable()
					dialog.ShowInformation("余额不足", detail, p.window)
					return
				}
				dialog.ShowConfirm("确认提现", detail+"\n\n是否继续？", func(confirmed bool) {
					if !confirmed {
						releaseBtn.Enable()
						return
					}
					logArea.SetText("")
					appendLog("开始提现...")
					go func() {
						defer fyne.Do(func() { releaseBtn.Enable() })
						ctx := context.Background()
						if err := p.svc.ReleaseERC20Tokens(ctx, splitter, token, appendLog); err != nil {
							appendLog(fmt.Sprintf("ERROR: %v", err))
						}
					}()
				}, p.window)
			})
		}()
	})

	return container.NewBorder(
		container.NewVBox(
			widget.NewForm(
				widget.NewFormItem("分账合约", splitterSelect),
				widget.NewFormItem("Token", tokenSelect),
			),
			container.NewHBox(queryBtn, releaseBtn),
			balanceLabel,
			widget.NewSeparator(),
		),
		nil, nil, nil,
		container.NewScroll(logArea),
	)
}
