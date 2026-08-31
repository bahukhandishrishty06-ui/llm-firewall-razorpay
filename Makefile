.PHONY: install frontend-install run frontend test eval dataset api docker-build docker-up clean

install:
	pip install -r requirements.txt
	pip install pytest
	cd frontend && npm install

frontend-install:
	cd frontend && npm install

dataset:
	python -m data.generate_attack_corpus

test:
	pytest tests/

eval:
	python -m evaluation.evaluate

run:
	docker compose up --build

frontend:
	cd frontend && npm run dev

api:
	uvicorn api.server:app --reload --port 8000

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache
