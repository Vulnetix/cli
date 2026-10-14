define make_target
$(1): ; @echo building $(1)
endef

$(foreach t,$(TARGETS),$(eval $(call make_target,$(t))))
