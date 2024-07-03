package com.example.demo.controller;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ui.Model;
import com.example.demo.model.User;
import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.util.Enumeration;
@Controller
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/register")
    public String showRegistrationForm() {
        return "register";
    }

    

    @GetMapping("/login")
    public String showLoginForm() {
        return "login";
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam("username") String username,
                            @RequestParam("password") String password,
                            HttpServletRequest request) {
        User user = userService.loginUser(username, password);
        if (user != null) {
            // 로그인 성공 시 세션에 사용자 정보 저장
            request.getSession().setAttribute("user", user);
            return "redirect:/";
        } else {
            return "redirect:/login?error";
        }
    }
    @GetMapping("/")
    public String home(Model model, HttpServletRequest request) {
        // 로그인 여부 확인
        User user = (User) request.getSession().getAttribute("user");
        if (user == null) {
            return "redirect:/login";
        }
    
        // 사용자 정보 모델에 추가
        model.addAttribute("user", user);
    
        // 접속 정보 모델에 추가
        model.addAttribute("remoteAddr", request.getRemoteAddr());
    
        // 모든 헤더 정보를 모델에 추가
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            model.addAttribute(headerName, headerValue);
        }
    
        return "home";
    }
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        request.getSession().invalidate();
        return "redirect:/login";
    }
    @PostMapping("/withdraw")
    public String withdrawUser(HttpServletRequest request) {
        User user = (User) request.getSession().getAttribute("user");
        if (user != null) {
            userService.withdrawUser(user);
            request.getSession().invalidate();
        }
        return "redirect:/login";
    }
    @PostMapping("/register")
    public String registerUser(@RequestParam("username") String username,
                               @RequestParam("password") String password,
                               @RequestParam("email") String email,
                               Model model) {
        User existingUser = userService.findByUsername(username);
        if (existingUser != null) {
            model.addAttribute("error", "이미 사용 중인 아이디입니다.");
            return "register";
        }
    
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        user.setEmail(email);
        userService.registerUser(user);
        return "redirect:/login";
    }
}


