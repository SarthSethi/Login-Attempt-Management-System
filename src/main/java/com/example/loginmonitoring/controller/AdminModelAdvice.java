package com.example.loginmonitoring.controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import com.example.loginmonitoring.service.AlertService;

/** Adds the number of open alerts (badge in the admin menu) to every admin page. */
@ControllerAdvice(assignableTypes = AdminController.class)
public class AdminModelAdvice {

    private final AlertService alertService;

    public AdminModelAdvice(AlertService alertService) {
        this.alertService = alertService;
    }

    @ModelAttribute
    public void addCommon(Model model) {
        model.addAttribute("openAlertCount", alertService.countOpen());
    }
}
