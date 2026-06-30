package pages

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// buildNonceDiagnoseTab Nonce 诊断/修复 Tab
func (p *MainPage) buildNonceDiagnoseTab() fyne.CanvasObject {
	resultLabel := widget.NewLabel("")
	resultLabel.Wrapping = fyne.TextWrapWord

	logArea := widget.NewMultiLineEntry()
	logArea.Wrapping = fyne.TextWrapWord
	logArea.TextStyle = fyne.TextStyle{Monospace: true}

	appendLog := func(msg string) {
		fyne.Do(func() {
			logArea.SetText(logArea.Text + msg + "\n")
		})
	}

	var fixBtn *widget.Button

	diagnoseBtn := widget.NewButton("诊断 Nonce", func() {
		wallet, _ := p.svc.GetCurrentWallet()
		if wallet == nil || wallet.Address == "" {
			dialog.ShowError(fmt.Errorf("请先导入商户钱包"), p.window)
			return
		}
		chain, _ := p.svc.GetCurrentChain()
		if chain == "" {
			dialog.ShowError(fmt.Errorf("请先选择链"), p.window)
			return
		}

		// 只对 EVM 链诊断
		chains, _ := p.svc.ListChains()
		var chainType string
		for _, c := range chains {
			if c.Chain == chain {
				chainType = c.ChainType
				break
			}
		}
		if chainType == "tron" {
			resultLabel.SetText("Tron 链不需要 Nonce 诊断（Tron 无 nonce 机制）")
			fixBtn.Hide()
			return
		}

		go func() {
			diag, err := p.svc.DiagnoseEvmNonce(chain, wallet.Address)
			if err != nil {
				fyne.Do(func() {
					resultLabel.SetText(fmt.Sprintf("诊断失败: %v", err))
					fixBtn.Hide()
				})
				return
			}

			info := fmt.Sprintf(
				"链: %s\n地址: %s\n\n"+
					"Latest Nonce (已确认): %d\n"+
					"Pending Nonce (含待处理): %d\n"+
					"卡住的交易数: %d",
				chain, diag.Address,
				diag.LatestNonce, diag.PendingNonce, diag.PendingCount,
			)

			if diag.HasPending {
				info += fmt.Sprintf("\n\n状态: 检测到 %d 笔卡住的交易，建议修复", diag.PendingCount)
			} else {
				info += "\n\n状态: 正常，无卡住的交易"
			}

			fyne.Do(func() {
				resultLabel.SetText(info)
				if diag.HasPending {
					fixBtn.Show()
				} else {
					fixBtn.Hide()
				}
			})
		}()
	})

	fixBtn = widget.NewButton("修复 Pending Nonce", func() {
		chain, _ := p.svc.GetCurrentChain()

		dialog.ShowConfirm("确认修复", "将对每个卡住的 nonce 发送 0 值自转交易进行覆盖。\n此操作会消耗少量 Gas 费用。\n\n是否继续？", func(confirmed bool) {
			if !confirmed {
				return
			}
			fixBtn.Disable()
			logArea.SetText("")
			go func() {
				defer fyne.Do(func() {
					fixBtn.Enable()
					// 修复后重新诊断
					diagnoseBtn.OnTapped()
				})
				ctx := context.Background()
				if err := p.svc.FixEvmPendingNonce(ctx, chain, appendLog); err != nil {
					appendLog(fmt.Sprintf("ERROR: %v", err))
				}
			}()
		}, p.window)
	})
	fixBtn.Hide()

	return container.NewBorder(
		container.NewVBox(
			diagnoseBtn,
			widget.NewSeparator(),
			resultLabel,
			fixBtn,
			widget.NewSeparator(),
		),
		nil, nil, nil,
		container.NewScroll(logArea),
	)
}
