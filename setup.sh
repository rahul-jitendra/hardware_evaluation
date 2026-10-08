#!/bin/bash
echo "============================================================"
echo " Setting up Decentralized PQC UAV Node on Raspberry Pi/ARM  "
echo "============================================================"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo ""
echo "[OK] Setup completed successfully. Ready to run drone_node.py"
