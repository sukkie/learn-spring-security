package com.in28minutes.learnspringsecurity.resource;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    private static List<Todo> todoList = List.of(new Todo("oykwon", "Learn AWS"),
            new Todo("oykwon", "Get AWS Certified"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos() {
        return todoList;
    }

    @GetMapping("/users/{username}/todos")
    public List<Todo> retrieveTodoForSpecificUser(@PathVariable String username) {
        return todoList.stream().filter(todo -> todo.username().equals(username)).toList();
    }

    @PostMapping("/users/{username}/todos")
    public void retrieveTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        System.out.println(todo);
    }
}

record Todo (String username, String description) {}
