# FishyBusiness

Automated fishing utility for Wizard101 built on the WizWalker framework.

## Overview

FishyBusiness automates the fishing minigame in Wizard101, allowing users to configure target fish parameters and run unattended fishing sessions.

## Features

- Configurable fish targeting by school, rank, size, and ID
- Chest fishing support
- Integrated speedhack module (pure Python, no external DLL required)
- Automatic fish detection and catch handling
- Graceful shutdown with signal handling

## Requirements

- Python 3.8+
- Windows OS
- [WizWalker](https://github.com/Deimos-Wizard101/wizwalker) library (Deimos-Wizard101 fork - actively maintained)
- Wizard101 client

**Note:** The original StarrFox/wizwalker repository is archived and no longer maintained. This project requires the Deimos-Wizard101 fork.

## Installation

1. Install dependencies:
   ```
   pip install git+https://github.com/Deimos-Wizard101/wizwalker@development --force-reinstall
   pip install loguru memobj
   ```

2. Configure target fish parameters at the top of `fish_gaming.py`

3. Launch Wizard101 and enter a fishing location

4. Run the script:
   ```
   python fish_gaming.py
   ```

## Configuration

Edit the configuration section at the top of `fish_gaming.py`:

| Parameter | Description | Default |
|-----------|-------------|---------|
| IS_CHEST | Target chest fish only | True |
| SCHOOL | Target school ("Any" for all) | "Any" |
| RANK | Target rank (0 for any) | 0 |
| ID | Specific fish ID (0 for any) | 0 |
| SIZE_MIN | Minimum fish size | 0 |
| SIZE_MAX | Maximum fish size | 999 |

### Speedhack Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| SPEEDHACK_ENABLED | Enable speed modification | True |
| SPEEDHACK_SPEED | Speed multiplier | 2 |

## Disclaimer

This software is provided for educational purposes only. Use at your own risk. The authors are not responsible for any consequences resulting from the use of this software.

## License

This project is provided as-is without warranty. See LICENSE for details.
