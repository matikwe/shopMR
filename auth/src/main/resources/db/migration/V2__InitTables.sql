create table resetoperations
(
    id serial primary key,
    users integer REFERENCES "users" (id),
    createdate timestamp DEFAULT current_timestamp,
    uuid varchar
)