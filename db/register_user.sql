INSERT INTO user (name, email, hash, admin)
VALUES ($1, $2, $3, $4)
returning id, name, email, admin;