package ru.istomin.JavaSpringData.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.istomin.JavaSpringData.model.Book;


@Repository
public interface BookRepository extends JpaRepository<Book,Long> {

}