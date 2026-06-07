package utils

import (
	"context"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"secureops/backend-go/api/config"
	"secureops/backend-go/api/model"
)

func Connect(ctx context.Context, cfg config.Config) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

func Close(database *gorm.DB) error {
	sqlDB, err := database.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func RunMigrations(ctx context.Context, database *gorm.DB) error {
	return database.WithContext(ctx).AutoMigrate(
		&model.User{},
		&model.Vulnerability{},
		&model.Asset{},
	)
}
