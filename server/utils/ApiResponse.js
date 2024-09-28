class ApiResponse {
  constructor(success, status, data, message) {
    this.success = success;
    this.status = status;
    this.data = data;
    this.message = message;
  }
}

export { ApiResponse };
