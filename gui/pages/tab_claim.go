package pages

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// buildClaimTab 资金归集 Tab
func (p *MainPage) buildClaimTab() fyne.CanvasObject {
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

	batchSizeEntry := widget.NewEntry()
	batchSizeEntry.SetText("50")

	infoLabel := widget.NewLabel("")
	infoLabel.Wrapping = fyne.TextWrapWord

	logArea := widget.NewMultiLineEntry()
	logArea.Wrapping = fyne.TextWrapWord
	logArea.TextStyle = fyne.TextStyle{Monospace: true}

	appendLog := func(msg string) {
		fyne.Do(func() {
			logArea.SetText(logArea.Text + msg + "\n")
		})
	}

	// 查询按钮 - 查询 receipt wallet 数量
	queryBtn := widget.NewButton("查询信息", func() {
		if splitterSelect.SelectedIndex() < 0 {
			dialog.ShowError(fmt.Errorf("请选择分账合约"), p.window)
			return
		}
		splitter := activeSplitters[splitterSelect.SelectedIndex()].Address

		go func() {
			count, err := p.svc.QueryReceiptWalletCount(splitter)
			if err != nil {
				fyne.Do(func() { infoLabel.SetText(fmt.Sprintf("查询失败: %v", err)) })
				return
			}
			info := fmt.Sprintf("Receipt Wallet 总数: %d", count)

			if tokenSelect.SelectedIndex() >= 0 {
				token := tokens[tokenSelect.SelectedIndex()].Contract
				balance, err := p.svc.QueryCollectableBalance(splitter, token)
				if err == nil {
					info += fmt.Sprintf(" | 可归集余额: %s (最小单位)", balance)
				}
			}
			fyne.Do(func() { infoLabel.SetText(info) })
		}()
	})

	var claimBtn *widget.Button
	claimBtn = widget.NewButton("开始归集", func() {
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

		var batchSize int
		if _, err := fmt.Sscanf(batchSizeEntry.Text, "%d", &batchSize); err != nil || batchSize <= 0 {
			dialog.ShowError(fmt.Errorf("批次大小必须为正整数"), p.window)
			return
		}

		claimBtn.Disable()
		go func() {
			est, err := p.svc.EstimateClaimFee(splitter, token, batchSize)
			if err != nil {
				fyne.Do(func() {
					claimBtn.Enable()
					dialog.ShowError(fmt.Errorf("费用评估失败: %v", err), p.window)
				})
				return
			}

			detail := fmt.Sprintf(
				"链: %s | Receipt Wallet 总数: %d\n"+
					"批次大小: %d | 预计批次数: %d\n\n"+
					"费用明细:\n"+
					"  预估单批手续费: %s %s\n"+
					"  预估总手续费 (×1.5): %s %s\n\n"+
					"当前钱包余额: %s %s",
				est.Chain, est.TotalReceipts,
				batchSize, est.BatchCount,
				est.EstimatedFee, est.NativeSymbol,
				est.TotalFee, est.NativeSymbol,
				est.WalletBalance, est.NativeSymbol,
			)

			if !est.Sufficient {
				detail += "\n\n余额不足，请充值后再试。"
			}

			fyne.Do(func() {
				if !est.Sufficient {
					claimBtn.Enable()
					dialog.ShowInformation("余额不足", detail, p.window)
					return
				}
				dialog.ShowConfirm("确认归集", detail+"\n\n是否继续？", func(confirmed bool) {
					if !confirmed {
						claimBtn.Enable()
						return
					}
					logArea.SetText("")
					appendLog(fmt.Sprintf("开始归集 %s, 每批 %d 个...", truncAddr(splitter), batchSize))
					go func() {
						defer fyne.Do(func() { claimBtn.Enable() })
						ctx := context.Background()
						if err := p.svc.ClaimReceiptERC20Tokens(ctx, splitter, token, batchSize, appendLog); err != nil {
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
				widget.NewFormItem("每批数量", batchSizeEntry),
			),
			container.NewHBox(queryBtn, claimBtn),
			infoLabel,
			widget.NewSeparator(),
		),
		nil, nil, nil,
		container.NewScroll(logArea),
	)
}
