package utils

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
	"github.com/microcosm-cc/bluemonday"
)

// Validator chứa các thành phần cho việc validate dữ liệu
type Validator struct {
	validator  *validator.Validate
	translator ut.Translator
	sanitizer  *bluemonday.Policy
}

// ValidationErrors là map chứa các lỗi validation
type ValidationErrors map[string]string

// NewValidator tạo một instance mới của Validator
func NewValidator() *Validator {
	// Khởi tạo validator
	validate := validator.New()

	// Khởi tạo translator
	english := en.New()
	uni := ut.New(english, english)
	trans, _ := uni.GetTranslator("en")

	// Đăng ký translations mặc định
	_ = en_translations.RegisterDefaultTranslations(validate, trans)

	// Đăng ký hàm để lấy tên trường từ json tag
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return fld.Name
		}
		return name
	})

	// Đăng ký các validator tùy chỉnh
	registerCustomValidators(validate)

	// Khởi tạo sanitizer
	sanitizer := bluemonday.UGCPolicy()

	return &Validator{
		validator:  validate,
		translator: trans,
		sanitizer:  sanitizer,
	}
}

// registerCustomValidators đăng ký các validator tùy chỉnh
func registerCustomValidators(v *validator.Validate) {
	// Validator kiểm tra mật khẩu mạnh
	_ = v.RegisterValidation("strongpassword", func(fl validator.FieldLevel) bool {
		password := fl.Field().String()

		// Kiểm tra độ dài
		if len(password) < 8 {
			return false
		}

		// Kiểm tra chữ thường
		if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
			return false
		}

		// Kiểm tra chữ hoa
		if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return false
		}

		// Kiểm tra số
		if !strings.ContainsAny(password, "0123456789") {
			return false
		}

		// Kiểm tra ký tự đặc biệt
		if !strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?/") {
			return false
		}

		return true
	})

	// Validator kiểm tra username hợp lệ
	_ = v.RegisterValidation("username", func(fl validator.FieldLevel) bool {
		username := fl.Field().String()

		// Username chỉ được phép chứa chữ cái, số, gạch dưới, gạch ngang
		matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", username)
		return matched
	})

	// Validator kiểm tra không có HTML
	_ = v.RegisterValidation("nohtml", func(fl validator.FieldLevel) bool {
		value := fl.Field().String()
		return !strings.Contains(value, "<") && !strings.Contains(value, ">")
	})
}

// Validate kiểm tra tính hợp lệ của một struct và trả về map các lỗi
func (v *Validator) Validate(data interface{}) (ValidationErrors, error) {
	// Nếu input không phải struct, trả về lỗi
	val := reflect.ValueOf(data)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil, errors.New("input is not a struct")
	}

	// Validate dữ liệu
	err := v.validator.Struct(data)
	if err == nil {
		return nil, nil
	}

	// Parse lỗi thành định dạng có thể đọc được
	validationErrors := make(ValidationErrors)

	if _, ok := err.(*validator.InvalidValidationError); ok {
		return nil, err
	}

	for _, err := range err.(validator.ValidationErrors) {
		field := err.Field()
		validationErrors[field] = err.Translate(v.translator)
	}

	return validationErrors, nil
}

// ValidateVar kiểm tra tính hợp lệ của một biến với tag validate cụ thể
func (v *Validator) ValidateVar(field interface{}, tag string) error {
	err := v.validator.Var(field, tag)
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return err
		}

		for _, e := range err.(validator.ValidationErrors) {
			return fmt.Errorf("%s: %s", e.Field(), e.Translate(v.translator))
		}
	}

	return nil
}

// SanitizeHTML loại bỏ các thẻ HTML không an toàn khỏi chuỗi
func (v *Validator) SanitizeHTML(input string) string {
	return v.sanitizer.Sanitize(input)
}

// SanitizeMap loại bỏ các thẻ HTML không an toàn từ tất cả giá trị chuỗi trong map
func (v *Validator) SanitizeMap(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range data {
		switch val := value.(type) {
		case string:
			result[key] = v.sanitizer.Sanitize(val)
		case []string:
			sanitized := make([]string, len(val))
			for i, s := range val {
				sanitized[i] = v.sanitizer.Sanitize(s)
			}
			result[key] = sanitized
		default:
			result[key] = value
		}
	}

	return result
}

// SanitizeStruct loại bỏ các thẻ HTML không an toàn từ tất cả trường string trong struct
func (v *Validator) SanitizeStruct(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Ptr {
		return errors.New("input must be a pointer to struct")
	}

	val = val.Elem()
	if val.Kind() != reflect.Struct {
		return errors.New("input must be a pointer to struct")
	}

	// Duyệt qua tất cả các trường của struct
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		if field.Kind() == reflect.String && field.CanSet() {
			sanitized := v.sanitizer.Sanitize(field.String())
			field.SetString(sanitized)
		}
	}

	return nil
}

// Format errors formats validation errors into a user-friendly format
func (v ValidationErrors) Format() []string {
	result := make([]string, 0, len(v))
	for field, message := range v {
		result = append(result, fmt.Sprintf("%s: %s", field, message))
	}
	return result
}

// HasErrors checks if there are any validation errors
func (v ValidationErrors) HasErrors() bool {
	return len(v) > 0
}

// Error implements the error interface for ValidationErrors
func (v ValidationErrors) Error() string {
	messages := v.Format()
	return strings.Join(messages, "; ")
}
