
docName = draft-ounsworth-pkix-key-attestation


default: all

txt: $(docName).txt

$(docName).txt: $(docName).mkd
	kdrfc $(docName).mkd



xml: $(docName).xml

$(docName).xml: $(docName).mkd
	kramdown-rfc2629 $(docName).mkd > $(docName).xml




html: all # xml
	# xml2rfc --no-dtd $(docName).xml --basename $(docName) --html
 # Explicitely aliasing this to `all` so that a .txt is always generated, because that should be committed to git for other people's ease of editing.

all: xml
	xml2rfc --no-dtd $(docName).xml --html --text


clean:
	rm -f $(docName).xml # $(docName).html # $(docName).txt
	# Explicitely not deleting the .html or .txt because that should be committed to git for other people's ease of editing.

# Run the mockup script to generate sample data
# See Dockerfile for dependencies.
mockup:
	ATTESTATION_DEMO_ROOT="$(shell pwd -P)/sampledata" python3 -m attestation demo

# Build a container image suitable for running the above targets
IMAGE=draft-ounsworth-pkix-key-attestation
container:
	docker build -t "$(IMAGE):latest" .

# Run any target inside a container
container-%:
	docker run --volume "$(shell pwd -P)":"$(shell pwd -P)" --workdir "$(shell pwd -P)" --user "$(shell id -u)" "$(IMAGE):latest" make $*
