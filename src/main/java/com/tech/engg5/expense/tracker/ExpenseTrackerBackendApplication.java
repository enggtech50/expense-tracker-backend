package com.tech.engg5.expense.tracker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import reactor.tools.agent.ReactorDebugAgent;

@SpringBootApplication
public class ExpenseTrackerBackendApplication {
  public static void main(String[] args) {
    ReactorDebugAgent.init();
    System.setProperty("APP_ID", "1100001");
    System.setProperty("APP_NAME", "expense-tracker-backend");
    SpringApplication application = new SpringApplication(ExpenseTrackerBackendApplication.class);
    application.run(args);
  }
}
