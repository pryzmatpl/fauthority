#ifndef SIGNING_STATUS_HPP
#define SIGNING_STATUS_HPP

enum class SigningStatus {
    Pending,
    Signed,
    Error,
    Rejected,
    NetworkError
};

#endif // SIGNING_STATUS_HPP