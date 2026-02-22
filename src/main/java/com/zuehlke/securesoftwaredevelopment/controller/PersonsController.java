package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.domain.Person;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.PersonRepository;
import com.zuehlke.securesoftwaredevelopment.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.sql.SQLException;
import java.util.List;

@Controller

public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonRepository.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('VIEW_PERSON')")
    public String person(@PathVariable int id, Model model, HttpSession session, Authentication authentication) {  //mora i ovde da se doda CSRF token jer i ovi endpointi renderuju person.html stranicu
        User currentUser = (User) authentication.getPrincipal();
        boolean hasUpdatePersonPermission = false;
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("UPDATE_PERSON".equals(authority.getAuthority())) {
                hasUpdatePersonPermission = true;
                break;
            }
        }
        boolean updatingOwnProfile = currentUser.getId() == id;
        if (!hasUpdatePersonPermission && !updatingOwnProfile) {
            throw new AccessDeniedException("You are not authorized to update this profile!");
        }

        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrf);
        model.addAttribute("person", personRepository.get("" + id));
        model.addAttribute("username", userRepository.findUsername(id));
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAnyAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication, HttpSession session) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrf);
        User user = (User) authentication.getPrincipal();
        model.addAttribute("person", personRepository.get("" + user.getId()));
        model.addAttribute("username", userRepository.findUsername(user.getId()));
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    public ResponseEntity<Void> person(@PathVariable int id, Authentication authentication) throws AccessDeniedException {
        User currentUser = (User) authentication.getPrincipal();
        boolean hasUpdatePersonPermission = false;
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("UPDATE_PERSON".equals(authority.getAuthority())) {
                hasUpdatePersonPermission = true;
                break;
            }
        }
        boolean updatingOwnProfile = currentUser.getId() == id;
        if (!hasUpdatePersonPermission && !updatingOwnProfile) {
            throw new AccessDeniedException("You are not authorized to delete this profile!");
        }

        personRepository.delete(id);
        userRepository.delete(id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    public String updatePerson(Person person, String username, HttpSession session, @RequestParam("csrfToken") String csrfToken, Authentication authentication) throws AccessDeniedException {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        if(!csrf.equals(csrfToken)) {
            throw new AccessDeniedException("You are not authorized to perform this action!");
        }

        User currentUser = (User) authentication.getPrincipal();
        boolean updatePerm = false;
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("UPDATE_PERSON".equals(authority.getAuthority())) {
                updatePerm = true;
                break;
            }
        }
        boolean updatingOwnProfile = String.valueOf(currentUser.getId()).equals(person.getId());
        if (!updatePerm && !updatingOwnProfile) {
            throw new AccessDeniedException("You are not authorized to update this profile!");
        }

        personRepository.update(person);
        userRepository.updateUsername(Integer.parseInt(person.getId()), username);
        return "redirect:/persons/" + person.getId();
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model, HttpSession session) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrf);
        model.addAttribute("persons", personRepository.getAll());
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    @ResponseBody
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        return personRepository.search(searchTerm);
    }
}