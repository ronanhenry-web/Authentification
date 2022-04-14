package com.example.securingweb;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

// This will be AUTO IMPLEMENTED by Spring into a Bean called UserLogginsRepository
// CRUD refers Create, Read, Update, Delete

public interface UserLogginsRepository extends CrudRepository<userloggins, Integer> {
	List<userloggins> findByUsername(String username);
}