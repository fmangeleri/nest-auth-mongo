import {
  Controller,
  Get,
  Query,
  Param,
  Post,
  Body,
  Put,
  Delete,
  HttpStatus,
  HttpCode,
  Res,
  // ParseIntPipe,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiTags, ApiOperation } from '@nestjs/swagger';

import { ParseIntPipe } from '../../common/parse-int.pipe';
import { CreateProductDto, UpdateProductDto } from '../dtos/products.dtos';
import { ProductsService } from './../services/products.service';
import { MongoIdPipe } from '../../common/mongoId.pipe';
import { FilterProductsDto } from '../dtos/products.dtos';

@ApiTags('products')
@Controller('products')
export class ProductsController {
  constructor(private productsService: ProductsService) {}

  @Get()
  @ApiOperation({ summary: 'List of products' })
  async getProducts(@Query() params: FilterProductsDto) {
    return await this.productsService.findAll(params);
  }

  @Get(':productId')
  @HttpCode(HttpStatus.ACCEPTED)
  async getOne(@Param('productId', MongoIdPipe) productId: string) {
    return await this.productsService.findOne(productId);
  }

  @Post()
  async create(@Body() payload: CreateProductDto) {
    return await this.productsService.create(payload);
  }

  @Put(':id')
  async update(
    @Param('id', MongoIdPipe) id: string,
    @Body() payload: UpdateProductDto,
  ) {
    return await this.productsService.update(id, payload);
  }

  @Delete(':id')
  async delete(@Param('id', MongoIdPipe) id: string) {
    return await this.productsService.remove(id);
  }
}
