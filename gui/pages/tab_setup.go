package pages

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// buildSetupTab 批量创建地址 Tab
func (p *MainPage) buildSetupTab() fyne.CanvasObject {
	// 每次进入都从后端强制刷新（同步加载，本地 API 调用 <100ms）
	currentChain, _ := p.svc.GetCurrentChain()
	if currentChain != "" {
		_ = p.svc.FetchSplitWallets(currentChain)
	}
	activeSplitters, splitterErr := p.svc.ListActiveSplitWallets()
	if splitterErr != nil {
		fmt.Printf("[批量创建] 加载分账合约失败: %v\n", splitterErr)
	}
	tokens, tokenErr := p.svc.ListTokensByChain(currentChain)
	if tokenErr != nil {
		fmt.Printf("[批量创建] 加载Token失败: %v\n", tokenErr)
	}
	fmt.Printf("[批量创建] 分账合约: %d 个, Token: %d 个\n", len(activeSplitters), len(tokens))

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

	statusLabel := widget.NewLabel(fmt.Sprintf("已加载 %d 个合约, %d 个Token", len(activeSplitters), len(tokens)))

	countEntry := widget.NewEntry()
	countEntry.SetText("10")

	logArea := widget.NewMultiLineEntry()
	logArea.Wrapping = fyne.TextWrapWord
	logArea.TextStyle = fyne.TextStyle{Monospace: true}

	appendLog := func(msg string) {
		fyne.Do(func() {
			logArea.SetText(logArea.Text + msg + "\n")
		})
	}

	var setupBtn *widget.Button
	setupBtn = widget.NewButton("开始批量创建", func() {
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

		var count int
		if _, err := fmt.Sscanf(countEntry.Text, "%d", &count); err != nil || count <= 0 {
			dialog.ShowError(fmt.Errorf("地址数量必须为正整数"), p.window)
			return
		}

		// 先评估费用
		setupBtn.Disable()
		go func() {
			est, err := p.svc.EstimateBatchSetupFee(splitter, count)
			if err != nil {
				fyne.Do(func() {
					setupBtn.Enable()
					dialog.ShowError(fmt.Errorf("费用评估失败: %v", err), p.window)
				})
				return
			}

			// 构建费用明细
			detail := fmt.Sprintf(
				"链: %s | 创建数量: %d\n\n"+
					"费用明细:\n"+
					"  每个 Receipt Wallet 需转入: %s %s\n"+
					"  Manager 需转入: %s %s\n"+
					"  转账手续费: %s %s\n"+
					"  ─────────────────────\n"+
					"  总计需要: %s %s\n"+
					"  最低余额要求 (×1.5): %s %s\n\n"+
					"当前钱包余额: %s %s",
				est.Chain, est.WalletCount,
				est.PerReceipt, est.NativeSymbol,
				est.ManagerTotal, est.NativeSymbol,
				est.TransferFee, est.NativeSymbol,
				est.TotalRequired, est.NativeSymbol,
				est.MinBalance, est.NativeSymbol,
				est.WalletBalance, est.NativeSymbol,
			)

			if !est.Sufficient {
				detail += "\n\n余额不足，请充值后再试。"
			}

			fyne.Do(func() {
				if !est.Sufficient {
					setupBtn.Enable()
					dialog.ShowInformation("余额不足", detail, p.window)
					return
				}

				// 弹出确认对话框
				dialog.ShowConfirm("确认批量创建", detail+"\n\n是否继续？", func(confirmed bool) {
					if !confirmed {
						setupBtn.Enable()
						return
					}

					// approve 金额使用 uint256 最大值
					amount := "115792089237316195423570985008687907853269984665640564039457584007913129639935"
					logArea.SetText("")
					appendLog(fmt.Sprintf("开始为 %s 批量创建 %d 个收款地址...", truncAddr(splitter), count))

					go func() {
						defer fyne.Do(func() { setupBtn.Enable() })

						ctx := context.Background()
						if err := p.svc.BatchSetup(ctx, splitter, token, amount, count, appendLog); err != nil {
							appendLog(fmt.Sprintf("❌ %v", err))
						}
					}()
				}, p.window)
			})
		}()
	})

	return container.NewBorder(
		container.NewVBox(
			statusLabel,
			widget.NewForm(
				widget.NewFormItem("分账合约", splitterSelect),
				widget.NewFormItem("Token", tokenSelect),
				widget.NewFormItem("地址数量", countEntry),
			),
			setupBtn,
			widget.NewSeparator(),
		),
		nil, nil, nil,
		container.NewScroll(logArea),
	)
}
