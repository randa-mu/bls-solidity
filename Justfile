alias t := test

test *args:
	@just test/data/generate
	forge t {{args}}

lint:
	forge fmt --check
	forge lint

format:
	forge fmt
	just test/data/format
