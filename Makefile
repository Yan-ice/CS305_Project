CONDA_PATH := ~/miniconda3
CONDA_ENV := cs305

PYTHON := $(CONDA_PATH)/envs/$(CONDA_ENV)/bin/python3

warn:	
	@echo ""
	@echo "##################################################"
	@echo ""
	@echo "MAKE SURE THE CORRECT CONDA ENVIRONMENT ACTIVATED!"
	@echo ""
	@echo "##################################################"
	@echo ""

clean: warn
	sudo mn -c

# Use 'make monitor to open monitor.
monitor: warn
	ryu-manager --observe-links controller.py 

# Use 'make test_switching' to start switching test.
test_switching: clean
	sudo $(PYTHON) tests/switching_test/test_network.py

# Use 'make test_dhcp' to start switching test.
test_dhcp: clean
	sudo $(PYTHON) tests/dhcp_test/test_network.py
