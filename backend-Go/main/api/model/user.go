package model

type User struct {
	ID           int64  `gorm:"primaryKey" json:"id"`
	Username     string `gorm:"not null" json:"username"`
	Email        string `gorm:"not null" json:"email"`
	PasswordHash string `gorm:"column:password_hash;not null" json:"-"`
}

func (User) TableName() string {
	return "users"
}

