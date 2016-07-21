CODE_DIR = src

.PHONY: vmi

vmi:
	$(MAKE) -C $(CODE_DIR)
	cp $(CODE_DIR)/vmi ./
clean:
	$(MAKE) -C $(CODE_DIR) clean
	rm -rf vmi
