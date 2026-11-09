# Developer shortcuts
api:        ## run the scan service on :8000
	cd server && python3 -m uvicorn app:app --port 8000

site:       ## build public/index.html against the local service
	CR_API=http://localhost:8000 python3 web/build.py

site-prod:  ## build against the hosted service (set CR_API)
	python3 web/build.py

selftest:   ## run the mutant self-test
	python3 engine/selftest.py

data:       ## rebuild benchmark data and labels (needs bench/fetch.sh first)
	python3 bench/make_data.py && python3 bench/make_reviews.py
