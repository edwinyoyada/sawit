/**
  This is the SQL script that will be used to initialize the database schema.
  We will evaluate you based on how well you design your database.
  1. How you design the tables.
  2. How you choose the data types and keys.
  3. How you name the fields.
  In this assignment we will use PostgreSQL as the database.
  */

CREATE TABLE public.users (
	id serial4 NOT NULL,
	phone varchar(13) NOT NULL,
	fullname varchar(60) NOT NULL,
	"password" varchar NOT NULL,
	login_times int4 NOT NULL DEFAULT 0,
	CONSTRAINT phone_un UNIQUE (phone),
	CONSTRAINT users_pk PRIMARY KEY (id)
);