package pages

import "fmt"

// stateToString 将 split wallet 状态码转为可读字符串
func stateToString(state int) string {
	switch {
	case state >= 7:
		return "ACTIVE"
	case state == 6:
		return "ACTIVATING"
	case state == 5:
		return "MANAGER_GENERATED"
	case state == 4:
		return "PENDING_MANAGER"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}

// truncAddr 截断地址显示
func truncAddr(addr string) string {
	if len(addr) <= 14 {
		return addr
	}
	return addr[:8] + "..." + addr[len(addr)-4:]
}
