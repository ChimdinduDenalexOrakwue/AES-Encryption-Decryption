.DEFAULT_GOAL := all

FILES1 :=                \
	   aes.py      \
	   utils.py    \

check: $(FILES)

format:
	autopep8 -i *.py

clean:
	rm -rf __pycache__
	rm -f *.pyc