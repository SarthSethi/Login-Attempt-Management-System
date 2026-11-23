package com.example.loginmonitoring.controller;

import java.time.Duration;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import com.example.loginmonitoring.entity.BlockSource;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.security.ClientIpResolver;
import com.example.loginmonitoring.service.AccountLockService;
import com.example.loginmonitoring.service.AdminAuditService;
import com.example.loginmonitoring.service.AlertService;
import com.example.loginmonitoring.service.AllowlistService;
import com.example.loginmonitoring.service.BlockedIpService;
import com.example.loginmonitoring.service.SessionTracker;
import com.example.loginmonitoring.service.SimulatorService;
import com.example.loginmonitoring.service.UserService;
import com.example.loginmonitoring.service.intel.IpIntelService;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Every change an administrator can make. All of them are POST requests protected by the CSRF
 * token, and every one is written to the audit log.
 */
@Controller
public class AdminActionController {

    private final BlockedIpService blockedIpService;
    private final AccountLockService accountLockService;
    private final AllowlistService allowlistService;
    private final AlertService alertService;
    private final AdminAuditService audit;
    private final UserService userService;
    private final SessionTracker sessionTracker;
    private final SimulatorService simulatorService;
    private final IpIntelService ipIntelService;
    private final ClientIpResolver clientIpResolver;

    public AdminActionController(BlockedIpService blockedIpService, AccountLockService accountLockService,
                                 AllowlistService allowlistService, AlertService alertService, AdminAuditService audit,
                                 UserService userService, SessionTracker sessionTracker,
                                 SimulatorService simulatorService, IpIntelService ipIntelService,
                                 ClientIpResolver clientIpResolver) {
        this.blockedIpService = blockedIpService;
        this.accountLockService = accountLockService;
        this.allowlistService = allowlistService;
        this.alertService = alertService;
        this.audit = audit;
        this.userService = userService;
        this.sessionTracker = sessionTracker;
        this.simulatorService = simulatorService;
        this.ipIntelService = ipIntelService;
        this.clientIpResolver = clientIpResolver;
    }

    // ---------------------------------------------------------------- IP blocks

    @PostMapping("/admin/ip/block")
    public String block(@RequestParam("ip") String rawIp,
                        @RequestParam(name = "duration", defaultValue = "24h") String duration,
                        @RequestParam(name = "reason", required = false) String reason,
                        @RequestParam(name = "back", required = false) String back,
                        Authentication auth, HttpServletRequest request, RedirectAttributes redirect) {
        String ip = ClientIpResolver.normalize(rawIp);
        if (ip == null) {
            redirect.addFlashAttribute("error", "Not a valid IP address.");
            return back(back, null);
        }
        if (ip.equals(clientIpResolver.resolve(request))) {
            redirect.addFlashAttribute("error", "You cannot block your own IP address (" + ip + ").");
            return back(back, ip);
        }
        if (allowlistService.isAllowlisted(ip)) {
            redirect.addFlashAttribute("error", ip + " is on the trusted list. Remove it from the list first.");
            return back(back, ip);
        }
        boolean permanent = "permanent".equals(duration);
        Optional<Duration> length = AdminController.parseDuration(duration);
        if (!permanent && length.isEmpty()) {
            redirect.addFlashAttribute("error", "Please choose how long to block the IP.");
            return back(back, ip);
        }
        String why = reason == null || reason.isBlank() ? "Blocked manually by an administrator" : reason.trim();
        blockedIpService.unblock(ip, auth.getName()); // replace any running block
        blockedIpService.blockManually(ip, permanent ? null : length.get(), "Manual: " + why, BlockSource.MANUAL,
                auth.getName(), false);
        audit.log(auth.getName(), permanent ? "BAN_IP" : "BLOCK_IP", ip, permanent ? "permanent" : duration + " - " + why);
        redirect.addFlashAttribute("message", permanent ? ip + " is now permanently banned."
                : ip + " is blocked for " + duration + ".");
        return back(back, ip);
    }

    @PostMapping("/admin/ip/unblock")
    public String unblock(@RequestParam("ip") String rawIp, @RequestParam(name = "back", required = false) String back,
                          Authentication auth, RedirectAttributes redirect) {
        String ip = ClientIpResolver.normalize(rawIp);
        if (ip == null) {
            redirect.addFlashAttribute("error", "Not a valid IP address.");
            return back(back, null);
        }
        int lifted = blockedIpService.unblock(ip, auth.getName());
        audit.log(auth.getName(), "UNBLOCK_IP", ip, lifted + " block(s) lifted");
        redirect.addFlashAttribute("message", lifted == 0 ? ip + " was not blocked." : ip + " has been unblocked.");
        return back(back, ip);
    }

    @PostMapping("/admin/ip/refresh")
    public String refreshLocation(@RequestParam("ip") String rawIp, Authentication auth, RedirectAttributes redirect) {
        String ip = ClientIpResolver.normalize(rawIp);
        if (ip != null) {
            var info = ipIntelService.lookupNow(ip);
            redirect.addFlashAttribute("message", "Location: " + info.getLocationLabel());
        }
        return back("ip", ip);
    }

    // ---------------------------------------------------------------- allow-list

    @PostMapping("/admin/allowlist/add")
    public String allowlistAdd(@RequestParam("cidr") String cidr,
                               @RequestParam(name = "note", required = false) String note,
                               @RequestParam(name = "back", required = false) String back,
                               Authentication auth, RedirectAttributes redirect) {
        try {
            String added = allowlistService.add(cidr, note, auth.getName());
            audit.log(auth.getName(), "ALLOWLIST_ADD", added, note);
            redirect.addFlashAttribute("message", added + " added to the trusted list. It will never be blocked "
                    + "automatically.");
            return back(back, ClientIpResolver.normalize(added));
        } catch (IllegalArgumentException ex) {
            redirect.addFlashAttribute("error", "Enter an IP address (203.0.113.7) or a range (203.0.113.0/24).");
            return back(back, null);
        }
    }

    @PostMapping("/admin/allowlist/{id}/delete")
    public String allowlistRemove(@PathVariable("id") long id, Authentication auth, RedirectAttributes redirect) {
        String removed = allowlistService.remove(id);
        audit.log(auth.getName(), "ALLOWLIST_REMOVE", removed, null);
        redirect.addFlashAttribute("message", (removed == null ? "Entry" : removed) + " removed from the trusted list.");
        return "redirect:/admin/protection";
    }

    // ---------------------------------------------------------------- account locks

    @PostMapping("/admin/locks/{id}/lift")
    public String liftLock(@PathVariable("id") long id, Authentication auth, RedirectAttributes redirect) {
        boolean done = accountLockService.lift(id, auth.getName());
        audit.log(auth.getName(), "LIFT_LOCK", "lock #" + id, null);
        redirect.addFlashAttribute("message", done ? "Lock lifted." : "Lock not found.");
        return "redirect:/admin/protection";
    }

    // ---------------------------------------------------------------- alerts

    @PostMapping("/admin/alerts/{id}/ack")
    public String acknowledge(@PathVariable("id") long id, @RequestParam(name = "back", required = false) String back,
                              Authentication auth, RedirectAttributes redirect) {
        if (alertService.acknowledge(id, auth.getName())) {
            audit.log(auth.getName(), "ACK_ALERT", "alert #" + id, null);
        }
        return "overview".equals(back) ? "redirect:/admin" : "redirect:/admin/alerts";
    }

    @PostMapping("/admin/alerts/ack-all")
    public String acknowledgeAll(Authentication auth, RedirectAttributes redirect) {
        int count = alertService.acknowledgeAll(auth.getName());
        audit.log(auth.getName(), "ACK_ALL_ALERTS", count + " alerts", null);
        redirect.addFlashAttribute("message", count + " alert(s) marked as handled.");
        return "redirect:/admin/alerts";
    }

    // ---------------------------------------------------------------- users

    @PostMapping("/admin/users/{id}/enable")
    public String enable(@PathVariable("id") long id, Authentication auth, RedirectAttributes redirect) {
        return setEnabled(id, true, auth, redirect);
    }

    @PostMapping("/admin/users/{id}/disable")
    public String disable(@PathVariable("id") long id, Authentication auth, RedirectAttributes redirect) {
        return setEnabled(id, false, auth, redirect);
    }

    private String setEnabled(long id, boolean enabled, Authentication auth, RedirectAttributes redirect) {
        Optional<User> target = userService.findById(id);
        if (target.isEmpty()) {
            redirect.addFlashAttribute("error", "User not found.");
            return "redirect:/admin/users";
        }
        if (target.get().getEmail().equalsIgnoreCase(auth.getName())) {
            redirect.addFlashAttribute("error", "You cannot disable your own account.");
            return "redirect:/admin/users";
        }
        userService.setEnabled(id, enabled);
        int signedOut = enabled ? 0 : sessionTracker.expireAll(target.get().getEmail());
        audit.log(auth.getName(), enabled ? "ENABLE_USER" : "DISABLE_USER", target.get().getEmail(),
                enabled ? null : signedOut + " session(s) signed out");
        redirect.addFlashAttribute("message", target.get().getEmail() + (enabled ? " enabled." : " disabled and signed out."));
        return "redirect:/admin/users";
    }

    @PostMapping("/admin/users/{id}/unlock")
    public String unlockUser(@PathVariable("id") long id, Authentication auth, RedirectAttributes redirect) {
        Optional<User> target = userService.findById(id);
        if (target.isPresent()) {
            int lifted = accountLockService.liftAllFor(target.get().getEmail(), auth.getName());
            audit.log(auth.getName(), "UNLOCK_USER", target.get().getEmail(), lifted + " lock(s) lifted");
            redirect.addFlashAttribute("message", lifted + " lock(s) on " + target.get().getEmail() + " lifted.");
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/admin/users/{id}/signout")
    public String signOutUser(@PathVariable("id") long id, Authentication auth, RedirectAttributes redirect) {
        Optional<User> target = userService.findById(id);
        if (target.isPresent()) {
            int count = target.get().getEmail().equalsIgnoreCase(auth.getName()) ? 0
                    : sessionTracker.expireAll(target.get().getEmail());
            audit.log(auth.getName(), "SIGN_OUT_USER", target.get().getEmail(), count + " session(s)");
            redirect.addFlashAttribute("message", count + " session(s) of " + target.get().getEmail() + " signed out.");
        }
        return "redirect:/admin/users";
    }

    // ---------------------------------------------------------------- simulator

    @PostMapping("/admin/simulator/run")
    public String runSimulation(@RequestParam("scenario") String scenario, @RequestParam("target") String target,
                                Authentication auth, RedirectAttributes redirect) {
        SimulatorService.Scenario chosen;
        try {
            chosen = SimulatorService.Scenario.valueOf(scenario);
        } catch (IllegalArgumentException ex) {
            redirect.addFlashAttribute("error", "Unknown scenario.");
            return "redirect:/admin/simulator";
        }
        try {
            SimulatorService.Result result = simulatorService.run(chosen, target);
            audit.log(auth.getName(), "RUN_SIMULATION", chosen.name(), "target " + result.target());
            redirect.addFlashAttribute("result", result);
        } catch (IllegalArgumentException ex) {
            redirect.addFlashAttribute("error", ex.getMessage());
        }
        return "redirect:/admin/simulator";
    }

    @PostMapping("/admin/simulator/clear")
    public String clearSimulation(Authentication auth, RedirectAttributes redirect) {
        int removed = simulatorService.clear();
        audit.log(auth.getName(), "CLEAR_SIMULATION", removed + " rows", null);
        redirect.addFlashAttribute("message", "Removed " + removed + " simulated records.");
        return "redirect:/admin/simulator";
    }

    /** Where to go after an action: back to the IP page, or to the protection page. */
    private static String back(String back, String ip) {
        if ("ip".equals(back) && ip != null) {
            return "redirect:" + UriComponentsBuilder.fromPath("/admin/ip").queryParam("ip", ip).toUriString();
        }
        return "redirect:/admin/protection";
    }
}
