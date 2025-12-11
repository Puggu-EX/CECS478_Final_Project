up:
	docker-compose up -d --build
demo:
	docker attach fp_client
kill:
	docker-compose kill
clean:
	docker-compose down

