#!/bin/bash

# Determine the directory where the script is located
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define the path for the virtual environment
VENV_DIR="${PROJECT_ROOT}/.venv"

# Check if .venv directory exists
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in ${VENV_DIR}"
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists in ${VENV_DIR}"
fi

echo "activating environment at ${VENV_DIR}" 
# Activate the virtual environment
source "$VENV_DIR/bin/activate"

# Install build tools if necessary
pip3 --require-virtualenv install setuptools 

# Upgrade pip to ensure compatibility
pip3 --require-virtualenv install --upgrade pip

# Install development dependencies
pip3 --require-virtualenv install -e .[dev]

echo -e """
  Setup complete. Virtual environment is ready.
  To activate in your terminal, run:

  source $VENV_DIR/bin/activate

  """