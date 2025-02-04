# Mira
_work in progress_

![Image](https://github.com/user-attachments/assets/0829b561-a15c-4dfe-bd74-5f0b10d47c90)


## About
Mira is a recon tool written in Python. Its goal is to eliminate some of the tedious tasks in information gathering.

## Main Features
* DNS scan
* Subdomain scan using wordlist
* Technology scan using whatweb and builtwith
* Custom port scanner
> note this was designed for use mainly on Linux distros so some features do not work fully on mac and Windows.

## Roadmap
* improve visual layout
* Web scraper
* Web crawler and DNS info of each url crawled
* wayback data
* generate report with findings

## Version
v0.3.8

## Usage
> mira_recon [arg] site-name [arg]

e.g.
> mira_recon -t example.com -Di

## Installation
> requires python3

> ### Linux path configuration
> ```
> echo 'export PATH="~/.local/bin:$PATH"' >> ~/.bashrc
> source ~/.bashrc
> ```

> ### Steps for installing
> ```
> pip install mira_recon
> ```
> ```
> python (or python3)
> 
> >>> import mira_recon
> >>> quit()
> ```
> 
> ```
> mira_recon -h
> ```
> If you run into errors like `command not found` double-check the path


## Contribute
If you're interested in contributing to the project, please do! <br />
I am constantly looking for ways to improve and add new features, and your contributions can help make this tool even more powerful and useful.<br />

## Some ways to contribute
* Report bugs or request new features by creating an issue on our GitHub repository.🐛
* Help us improve the documentation by submitting updates or corrections.📚
* Contribute code by submitting pull requests with bug fixes or new features.💻
* Any help is greatly appreciated

