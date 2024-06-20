package ru.istomin.JavaSpringData.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import ru.istomin.JavaSpringData.model.Reader;


@Repository
public interface ReaderRepository extends JpaRepository<Reader,Long> {

}
