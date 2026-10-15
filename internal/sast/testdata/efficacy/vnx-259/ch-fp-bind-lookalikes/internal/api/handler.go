package api

func (h *Handler) Create(c *gin.Context) {
	var req CreateRequest
	if err := c.Bind(&req); err != nil {
		return
	}
	if err := h.ldap.Bind(h.cfg.BindDN, h.cfg.BindPassword); err != nil {
		return
	}
}
