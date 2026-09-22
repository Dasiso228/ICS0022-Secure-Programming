# Secure CLI Password Manager
Secure CLI Password Manager is a command-line password management application developed for the **Secure Programming (ICS0022)** course at Tallinn University of Technology.

The goal of the project is to create a small password manager with a strong focus on secure software development practices.

## Project Scope

The application will allow a user to securely store and manage credentials locally through a command-line interface.

The password manager will use a master password to unlock an encrypted password vault.

The initial version is planned as a single-user local application.

The project will focus on:

* secure authentication using a master password;
* encrypted storage of credentials;
* protection of the password vault against unauthorized modification;
* secure handling of passwords and encryption keys in memory;
* input validation;
* secure file handling;
* safe error handling;
* logging of relevant security events;
* security testing of the final application.

## Planned Features

The password manager is planned to support the following operations:

* initialize a new password vault;
* unlock the vault using a master password;
* add a credential;
* list stored credential names;
* retrieve a credential;
* edit an existing credential;
* delete a credential;
* lock the vault.

A stored credential may contain:

* entry name;
* username;
* password;
* website or service name;
* optional notes.

## Planned CLI Commands

Example commands:

```bash
password-manager init
password-manager add
password-manager list
password-manager get <entry>
password-manager edit <entry>
password-manager delete <entry>
password-manager lock
```

The exact command structure may change during implementation.

## Security Design

The password vault will not store credentials in plaintext.

The master password will be processed using a password-based key derivation function such as **Argon2id**.

The derived encryption key will be used to encrypt the vault using authenticated encryption, currently planned to use **AES-GCM**.

The project will also consider:

* protection against brute-force attacks;
* secure generation and storage of salts and nonces;
* detection of vault modification;
* safe handling of sensitive data in memory;
* secure file permissions;
* input validation;
* secure error handling.

## Technology

Planned implementation:

* **Language:** Python 3
* **Interface:** Command Line Interface (CLI)
* **Password/key derivation:** Argon2id
* **Authenticated encryption:** AES-GCM
* **Platform:** Linux, macOS

The final libraries and implementation details may change during development.

## Project Status

Current stage:

**Checkpoint 1 — Threat Model and Architecture**

Checkpoint 1 focuses on the architecture of the password manager, threat modelling, cryptographic design, and initial project structure.

Implementation of the main password manager functionality will follow in later checkpoints.

## Running the Project

The project is currently in the design stage and does not yet contain the final executable application.

Future versions are expected to run using Python 3.

Example:

```bash
python main.py
```

More detailed build and run instructions will be added as implementation progresses.

