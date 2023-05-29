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
	@echo "HELP: switch sX stop/start"
	@echo "HELP: link hX sX down/up"
	@echo "HELP: sh ovs-ofctl mod-port sX 1 down"
	@echo ""

clean: warn
	sudo mn -c
	sudo rm -f /var/lib/dhcp/dhclient.leases

# Use 'make monitor to open monitor.
monitor: clean
	ryu-manager --observe-links controller.py 

# Use 'make test switching' to start switching test.
test_dns: warn
	@echo "========================"
	@echo "                    "
	@echo "  h1 - s1 -- s2 - h2 "
	@echo "         \  /   "
	@echo "          s3 "
	@echo "          |   "
	@echo "          h3  "
	@echo "            "
	@echo "========================"
	sudo $(PYTHON) tests/switching_test/test_triangle.py

test_switching: warn
	@echo "========================"
	@echo "                    "
	@echo "          s2 \      "
	@echo "  h1 \   /    s3 - h4  "
	@echo "  h2 - s1      |      "
	@echo "  h3 /   \    s4 - h5  "
	@echo "          s5 /  \       "
	@echo "                 s6 - h6"
	@echo "                "
	@echo "========================"
	sudo $(PYTHON) tests/switching_test/test_complex.py

# Use 'make test dhcp' to start switching test.
test_dhcp: warn
	sudo $(PYTHON) tests/dhcp_test/test_network.py


test_ins1: warn
	sudo $(PYTHON) tests/my_dhcp_test/test_ins1.py

test_ins234: warn
	@echo "========================"
	@echo "                    "
	@echo "  h1 \   "
	@echo "  .. - s1   "
	@echo "  hN /  "
	@echo "                "
	@echo "========================"
	sudo $(PYTHON) tests/my_dhcp_test/test_ins2_3_4.py

test_lease: warn
	sudo $(PYTHON) tests/my_dhcp_test/test_lease_time.py


