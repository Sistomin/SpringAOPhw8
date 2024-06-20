package ru.istomin.JavaSpringData.service;

import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.istomin.JavaSpringData.model.Book;
import ru.istomin.JavaSpringData.model.Reader;
import ru.istomin.JavaSpringData.repository.BookRepository;
import ru.istomin.JavaSpringData.repository.IssueRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class BookService {
    private final BookRepository bookRepository;
    private final IssueRepository issueRepository;

    @Autowired
    public BookService(BookRepository bookRepository, IssueRepository issueRepository) {
        this.bookRepository = bookRepository;
        this.issueRepository = issueRepository;
    }

    // получить книгу по id
    public Book getBookById(Long id) {
        Optional<Book> optionalBook =bookRepository.findById(id);
        if(optionalBook.isPresent()){
            return optionalBook.get();
        } else {
            throw new NullPointerException("Book not found.");
        }
    }

    //получить список всех книг
    public List<Book> getAllBooks() {
        return bookRepository.findAll();
    }

    // создание книги
    public Book addBook(Book book){
        return bookRepository.save(book);
    }

    //обновление книг
    @Transactional
    public Book updateBooks(Long id, Book book){
        Book updateBook = bookRepository.findById(id).orElseThrow(()-> new RuntimeException("Book not found"));
        updateBook.setName(book.getName());
        return bookRepository.save(updateBook);
    }

    // удаление книги
    public void deleteBook(Long id){
        bookRepository.deleteById(id);
    }


}