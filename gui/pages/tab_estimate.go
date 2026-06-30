package pages

import (
	"fmt"
	"hashnut-mpc-client/util/tx_util"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// buildEstimateTab Gas 评估 Tab
func (p *MainPage) buildEstimateTab() fyne.CanvasObject {
	// 同步刷新 split wallet 列表
	currentChain, _ := p.svc.GetCurrentChain()
	if currentChain != "" {
		_ = p.svc.FetchSplitWallets(currentChain)
	}
	activeSplitters, _ := p.svc.ListActiveSplitWallets()
	splitterOpts := make([]string, len(activeSplitters))
	for i, sw := range activeSplitters {
		label := truncAddr(sw.Address)
		if sw.Alias != "" {
			label = fmt.Sprintf("%s (%s)", sw.Alias, truncAddr(sw.Address))
		}
		splitterOpts[i] = label
	}
	splitterSelect := widget.NewSelect(splitterOpts, nil)
	if len(splitterOpts) > 0 {
		splitterSelect.SetSelectedIndex(0)
	}

	countEntry := widget.NewEntry()
	countEntry.SetText("10")

	resultLabel := widget.NewLabel("")
	resultLabel.Wrapping = fyne.TextWrapWord

	estimateBtn := widget.NewButton("评估 Gas 费用", func() {
		if splitterSelect.SelectedIndex() < 0 || splitterSelect.SelectedIndex() >= len(activeSplitters) {
			dialog.ShowError(fmt.Errorf("请选择分账合约"), p.window)
			return
		}
		splitter := activeSplitters[splitterSelect.SelectedIndex()].Address
		var count int
		if _, err := fmt.Sscanf(countEntry.Text, "%d", &count); err != nil || count <= 0 {
			dialog.ShowError(fmt.Errorf("地址数量必须为正整数"), p.window)
			return
		}

		est, err := p.svc.EstimateBatchSetup(splitter, count)
		if err != nil {
			dialog.ShowError(err, p.window)
			return
		}

		suffIcon := "充足"
		if !est.Sufficient {
			suffIcon = "不足"
		}
		resultLabel.SetText(fmt.Sprintf(
			"链: %s | Gas Price: %s gwei\n"+
				"每个 receipt wallet: %s %s\n"+
				"manager: %s %s\n"+
				"转 gas 手续费: %s %s\n"+
				"总计: %s %s\n"+
				"当前余额: %s %s [%s]",
			est.Chain, tx_util.FormatGwei(est.GasPrice),
			tx_util.FormatWeiToETH(est.PerReceiptWallet), est.NativeSymbol,
			tx_util.FormatWeiToETH(est.ManagerTotal), est.NativeSymbol,
			tx_util.FormatWeiToETH(est.FundingFeeTotal), est.NativeSymbol,
			tx_util.FormatWeiToETH(est.MerchantTotal), est.NativeSymbol,
			tx_util.FormatWeiToETH(est.MerchantBalance), est.NativeSymbol, suffIcon,
		))
	})

	return container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("分账合约", splitterSelect),
			widget.NewFormItem("地址数量", countEntry),
		),
		estimateBtn,
		widget.NewSeparator(),
		resultLabel,
	)
}
